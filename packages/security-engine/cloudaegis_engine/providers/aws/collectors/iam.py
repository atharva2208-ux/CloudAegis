"""IAM discovery: account settings, users, groups, roles and customer managed policies."""

from __future__ import annotations

from typing import Any, Iterator

from cloudaegis_engine import resource_types as rt
from cloudaegis_engine.models import Relationship, Resource
from cloudaegis_engine.providers.aws.collectors import CollectorContext
from cloudaegis_engine.providers.aws.collectors._util import call, iso, mask_key_id, policy_doc, tags_to_dict

GLOBAL = "global"


def _default_version_doc(versions: list[dict[str, Any]]) -> dict[str, Any] | None:
    for version in versions or []:
        if version.get("IsDefaultVersion"):
            return policy_doc(version.get("Document"))
    return None


class _ManagedPolicyResolver:
    """Resolves attached managed policy documents, caching by ARN."""

    def __init__(self, iam: Any, local: dict[str, dict[str, Any]]) -> None:
        self.iam = iam
        self.cache: dict[str, dict[str, Any] | None] = {arn: doc for arn, doc in local.items()}

    def document(self, arn: str) -> dict[str, Any] | None:
        if arn not in self.cache:
            policy = call(self.iam.get_policy, PolicyArn=arn, default={}).get("Policy", {})
            version = policy.get("DefaultVersionId")
            doc = None
            if version:
                pv = call(self.iam.get_policy_version, PolicyArn=arn, VersionId=version, default={})
                doc = policy_doc(pv.get("PolicyVersion", {}).get("Document"))
            self.cache[arn] = doc
        return self.cache[arn]

    def entries(self, attached: list[dict[str, Any]], source: str) -> list[dict[str, Any]]:
        out = []
        for item in attached or []:
            doc = self.document(item["PolicyArn"])
            if doc:
                out.append({"name": item["PolicyName"], "source": source, "document": doc})
        return out


def _paginate_auth_details(iam: Any) -> dict[str, list[dict[str, Any]]]:
    merged: dict[str, list[dict[str, Any]]] = {"UserDetailList": [], "GroupDetailList": [], "RoleDetailList": [], "Policies": []}
    paginator = iam.get_paginator("get_account_authorization_details")
    for page in paginator.paginate(Filter=["User", "Role", "Group", "LocalManagedPolicy"]):
        for key in merged:
            merged[key].extend(page.get(key, []))
    return merged


def _account(ctx: CollectorContext, iam: Any) -> Resource:
    summary = call(iam.get_account_summary, default={}).get("SummaryMap", {})
    raw_policy = call(iam.get_account_password_policy, missing=("NoSuchEntity",), default=None)
    password_policy = None
    if raw_policy:
        p = raw_policy.get("PasswordPolicy", {})
        password_policy = {
            "minimum_length": p.get("MinimumPasswordLength"),
            "require_symbols": p.get("RequireSymbols"),
            "require_numbers": p.get("RequireNumbers"),
            "require_uppercase": p.get("RequireUppercaseCharacters"),
            "require_lowercase": p.get("RequireLowercaseCharacters"),
            "max_password_age": p.get("MaxPasswordAge"),
            "password_reuse_prevention": p.get("PasswordReusePrevention"),
        }
    s3control = ctx.client("s3control")
    bpa_raw = call(
        s3control.get_public_access_block,
        AccountId=ctx.account_id,
        missing=("NoSuchPublicAccessBlockConfiguration",),
        default=None,
    )
    bpa = None
    if bpa_raw:
        c = bpa_raw.get("PublicAccessBlockConfiguration", {})
        bpa = {
            "block_public_acls": c.get("BlockPublicAcls", False),
            "ignore_public_acls": c.get("IgnorePublicAcls", False),
            "block_public_policy": c.get("BlockPublicPolicy", False),
            "restrict_public_buckets": c.get("RestrictPublicBuckets", False),
        }
    props: dict[str, Any] = {
        "account_id": ctx.account_id,
        "password_policy": password_policy,
        "s3_public_access_block": bpa,
        "users": summary.get("Users"),
        "roles": summary.get("Roles"),
    }
    if "AccountMFAEnabled" in summary:
        props["root_mfa_enabled"] = bool(summary["AccountMFAEnabled"])
    if "AccountAccessKeysPresent" in summary:
        props["root_access_keys_present"] = bool(summary["AccountAccessKeysPresent"])
    return Resource(
        uid=f"arn:{ctx.partition}:iam::{ctx.account_id}:root",
        resource_type=rt.AWS_ACCOUNT,
        service="IAM",
        name=f"AWS account {ctx.account_id}",
        region=GLOBAL,
        account_id=ctx.account_id,
        properties=props,
    )


def _user(ctx: CollectorContext, iam: Any, detail: dict[str, Any], resolver: _ManagedPolicyResolver,
          group_docs: dict[str, list[dict[str, Any]]], users_by_name: dict[str, dict[str, Any]]) -> Resource:
    name = detail["UserName"]
    profile = call(iam.get_login_profile, UserName=name, missing=("NoSuchEntity",), default=None)
    mfa = call(iam.list_mfa_devices, UserName=name, default={}).get("MFADevices", [])
    keys = []
    for key in call(iam.list_access_keys, UserName=name, default={}).get("AccessKeyMetadata", []):
        last = call(iam.get_access_key_last_used, AccessKeyId=key["AccessKeyId"], default={})
        keys.append({
            "access_key_id": mask_key_id(key["AccessKeyId"]),
            "status": key.get("Status"),
            "created_at": iso(key.get("CreateDate")),
            "last_used_at": iso(last.get("AccessKeyLastUsed", {}).get("LastUsedDate")),
        })
    docs = [
        {"name": p["PolicyName"], "source": "inline", "document": policy_doc(p.get("PolicyDocument"))}
        for p in detail.get("UserPolicyList", [])
    ]
    docs += resolver.entries(detail.get("AttachedManagedPolicies", []), "attached")
    for group in detail.get("GroupList", []):
        docs += group_docs.get(group, [])
    password_last_used = users_by_name.get(name, {}).get("PasswordLastUsed")
    return Resource(
        uid=detail["Arn"],
        resource_type=rt.IAM_USER,
        service="IAM",
        name=name,
        region=GLOBAL,
        account_id=ctx.account_id,
        tags=tags_to_dict(detail.get("Tags")),
        properties={
            "user_name": name,
            "created_at": iso(detail.get("CreateDate")),
            "password_enabled": profile is not None,
            "password_last_used": iso(password_last_used),
            "mfa_enabled": bool(mfa),
            "mfa_devices": len(mfa),
            "access_keys": keys,
            "groups": detail.get("GroupList", []),
            "attached_policies": [
                {"name": p["PolicyName"], "arn": p["PolicyArn"]} for p in detail.get("AttachedManagedPolicies", [])
            ],
            "policy_documents": [d for d in docs if d.get("document")],
        },
        relationships=[
            Relationship("member_of", f"arn:{ctx.partition}:iam::{ctx.account_id}:group/{g}")
            for g in detail.get("GroupList", [])
        ],
    )


def collect(ctx: CollectorContext) -> Iterator[Resource]:
    iam = ctx.client("iam")
    yield _account(ctx, iam)

    details = _paginate_auth_details(iam)
    local_docs: dict[str, dict[str, Any]] = {}
    for policy in details["Policies"]:
        doc = _default_version_doc(policy.get("PolicyVersionList", []))
        if doc:
            local_docs[policy["Arn"]] = doc
    resolver = _ManagedPolicyResolver(iam, local_docs)

    group_docs: dict[str, list[dict[str, Any]]] = {}
    for group in details["GroupDetailList"]:
        docs = [
            {"name": p["PolicyName"], "source": f"group:{group['GroupName']}", "document": policy_doc(p.get("PolicyDocument"))}
            for p in group.get("GroupPolicyList", [])
        ]
        docs += resolver.entries(group.get("AttachedManagedPolicies", []), f"group:{group['GroupName']}")
        group_docs[group["GroupName"]] = [d for d in docs if d.get("document")]
        yield Resource(
            uid=group["Arn"],
            resource_type=rt.IAM_GROUP,
            service="IAM",
            name=group["GroupName"],
            region=GLOBAL,
            account_id=ctx.account_id,
            properties={
                "group_name": group["GroupName"],
                "created_at": iso(group.get("CreateDate")),
                "attached_policies": [
                    {"name": p["PolicyName"], "arn": p["PolicyArn"]} for p in group.get("AttachedManagedPolicies", [])
                ],
                "policy_documents": group_docs[group["GroupName"]],
            },
        )

    users_by_name: dict[str, dict[str, Any]] = {}
    for page in iam.get_paginator("list_users").paginate():
        for user in page.get("Users", []):
            users_by_name[user["UserName"]] = user

    for detail in details["UserDetailList"]:
        yield _user(ctx, iam, detail, resolver, group_docs, users_by_name)

    for role in details["RoleDetailList"]:
        docs = [
            {"name": p["PolicyName"], "source": "inline", "document": policy_doc(p.get("PolicyDocument"))}
            for p in role.get("RolePolicyList", [])
        ]
        docs += resolver.entries(role.get("AttachedManagedPolicies", []), "attached")
        yield Resource(
            uid=role["Arn"],
            resource_type=rt.IAM_ROLE,
            service="IAM",
            name=role["RoleName"],
            region=GLOBAL,
            account_id=ctx.account_id,
            tags=tags_to_dict(role.get("Tags")),
            properties={
                "role_name": role["RoleName"],
                "path": role.get("Path"),
                "created_at": iso(role.get("CreateDate")),
                "is_service_linked": role.get("Path", "").startswith("/aws-service-role/"),
                "trust_policy": policy_doc(role.get("AssumeRolePolicyDocument")),
                "last_used_at": iso((role.get("RoleLastUsed") or {}).get("LastUsedDate")),
                "attached_policies": [
                    {"name": p["PolicyName"], "arn": p["PolicyArn"]} for p in role.get("AttachedManagedPolicies", [])
                ],
                "policy_documents": [d for d in docs if d.get("document")],
            },
        )

    for policy in details["Policies"]:
        yield Resource(
            uid=policy["Arn"],
            resource_type=rt.IAM_POLICY,
            service="IAM",
            name=policy["PolicyName"],
            region=GLOBAL,
            account_id=ctx.account_id,
            properties={
                "policy_name": policy["PolicyName"],
                "attachment_count": policy.get("AttachmentCount", 0),
                "default_version": policy.get("DefaultVersionId"),
                "document": local_docs.get(policy["Arn"]),
                "created_at": iso(policy.get("CreateDate")),
            },
        )
