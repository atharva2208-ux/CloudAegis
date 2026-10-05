"""IAM detection rules."""

from __future__ import annotations

from cloudaegis_engine import resource_types as rt
from cloudaegis_engine.checks import policy as pol
from cloudaegis_engine.checks.timeutil import age_days
from cloudaegis_engine.models import Resource, RuleMetadata, RuleResult, Severity
from cloudaegis_engine.rules.aws import _refs
from cloudaegis_engine.rules.base import Rule, RuleContext
from cloudaegis_engine.rules.registry import register

ADMIN_MANAGED_POLICY_ARNS = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
}


def principal_admin_sources(resource: Resource) -> list[str]:
    """Names of policies that give this user/role/group full admin rights."""
    sources = [
        name
        for name, doc in pol.iter_documents(resource.prop("policy_documents", []))
        if pol.grants_full_admin(doc)
    ]
    for attached in resource.prop("attached_policies", []) or []:
        if attached.get("arn") in ADMIN_MANAGED_POLICY_ARNS and attached.get("name") not in sources:
            sources.append(attached.get("name"))
    return sources


def _console_user(resource: Resource) -> bool:
    return bool(resource.prop("password_enabled"))


@register
class RootMfaDisabled(Rule):
    metadata = RuleMetadata(
        rule_id="IAM-001",
        title="Root account MFA is not enabled",
        severity=Severity.CRITICAL,
        service="IAM",
        category="Identity & Access",
        resource_type=rt.AWS_ACCOUNT,
        description="The AWS account root user does not have a multi-factor authentication device registered.",
        impact="The root user has unrestricted access to every resource and billing setting. "
        "A compromised root password alone is enough for full account takeover.",
        remediation="Register a hardware or virtual MFA device for the root user and store recovery "
        "information securely.",
        remediation_steps=(
            "Sign in as the root user and open Security credentials.",
            "Under Multi-factor authentication, choose Assign MFA device.",
            "Prefer a hardware security key; store backup details in a controlled vault.",
        ),
        references=(_refs.IAM_ROOT_MFA, _refs.CIS_AWS),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        enabled = resource.prop("root_mfa_enabled")
        if enabled is None:
            return None
        return self.check(resource, not enabled, {"AccountMFAEnabled": bool(enabled)})


@register
class RootAccessKeysPresent(Rule):
    metadata = RuleMetadata(
        rule_id="IAM-002",
        title="Root account has active access keys",
        severity=Severity.CRITICAL,
        service="IAM",
        category="Identity & Access",
        resource_type=rt.AWS_ACCOUNT,
        description="Programmatic access keys exist for the AWS account root user.",
        impact="Root access keys provide unrestricted API access and cannot be limited by IAM "
        "policies. Leaked keys result in total account compromise.",
        remediation="Delete the root user's access keys and use IAM roles for programmatic access.",
        remediation_steps=(
            "Sign in as the root user and open Security credentials.",
            "Deactivate, then delete every access key listed for the root user.",
            "Replace any automation that used them with an IAM role.",
        ),
        references=(_refs.IAM_BEST_PRACTICES, _refs.CIS_AWS),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        present = resource.prop("root_access_keys_present")
        if present is None:
            return None
        return self.check(resource, bool(present), {"AccountAccessKeysPresent": int(bool(present))})


@register
class ConsoleUserWithoutMfa(Rule):
    metadata = RuleMetadata(
        rule_id="IAM-003",
        title="IAM user with console access has no MFA",
        severity=Severity.HIGH,
        service="IAM",
        category="Identity & Access",
        resource_type=rt.IAM_USER,
        description="An IAM user can sign in to the AWS Management Console with a password but has "
        "no MFA device.",
        impact="Phished, reused or brute-forced passwords give an attacker interactive console access.",
        remediation="Require MFA for every console user, or move users to IAM Identity Center with "
        "enforced MFA.",
        remediation_steps=(
            "Enable an MFA device for the user.",
            "Attach a policy that denies actions when aws:MultiFactorAuthPresent is false.",
            "Consider federating console access through IAM Identity Center.",
        ),
        remediation_cli="aws iam list-mfa-devices --user-name <user>",
        references=(_refs.IAM_BEST_PRACTICES, _refs.CIS_AWS),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        if not _console_user(resource):
            return None
        mfa = bool(resource.prop("mfa_enabled"))
        return self.check(
            resource,
            not mfa,
            {"PasswordEnabled": True, "MFAEnabled": mfa, "MFADevices": resource.prop("mfa_devices", 0)},
        )


@register
class UnusedAccessKey(Rule):
    metadata = RuleMetadata(
        rule_id="IAM-004",
        title="Active access key unused for 90+ days",
        severity=Severity.MEDIUM,
        service="IAM",
        category="Identity & Access",
        resource_type=rt.IAM_USER,
        description="An IAM user has an active access key that has not been used in the configured "
        "inactivity window.",
        impact="Dormant credentials are rarely monitored and widen the attack surface without "
        "providing business value.",
        remediation="Deactivate unused access keys and delete them after confirming nothing depends on them.",
        remediation_steps=(
            "Confirm with the key owner that the key is not required.",
            "Deactivate the key and monitor for breakage.",
            "Delete the key after the observation period.",
        ),
        remediation_cli="aws iam update-access-key --user-name <user> --access-key-id <key-id> --status Inactive",
        references=(_refs.IAM_ACCESS_KEYS, _refs.CIS_AWS),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        keys = [k for k in resource.prop("access_keys", []) or [] if k.get("status") == "Active"]
        if not keys:
            return None
        stale = []
        for key in keys:
            last = key.get("last_used_at") or key.get("created_at")
            days = age_days(last, ctx.now)
            if days is not None and days >= ctx.stale_credential_days:
                stale.append({"AccessKeyId": key.get("access_key_id"), "DaysSinceLastUse": days,
                              "LastUsed": key.get("last_used_at") or "never"})
        return self.check(resource, bool(stale), {"UnusedActiveKeys": stale, "ThresholdDays": ctx.stale_credential_days})


@register
class AccessKeyNotRotated(Rule):
    metadata = RuleMetadata(
        rule_id="IAM-005",
        title="Access key not rotated in 90+ days",
        severity=Severity.MEDIUM,
        service="IAM",
        category="Identity & Access",
        resource_type=rt.IAM_USER,
        description="An active access key is older than the rotation threshold.",
        impact="Long-lived keys accumulate exposure in source code, CI logs and laptops. Rotation "
        "limits the useful lifetime of a leaked key.",
        remediation="Create a new key, update consumers, then deactivate and delete the old key. "
        "Prefer IAM roles with temporary credentials.",
        remediation_steps=(
            "Create a second access key for the user.",
            "Update all applications to the new key.",
            "Deactivate and delete the old key.",
        ),
        remediation_cli="aws iam create-access-key --user-name <user>",
        references=(_refs.IAM_ACCESS_KEYS, _refs.CIS_AWS),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        keys = [k for k in resource.prop("access_keys", []) or [] if k.get("status") == "Active"]
        if not keys:
            return None
        old = []
        for key in keys:
            days = age_days(key.get("created_at"), ctx.now)
            if days is not None and days >= ctx.stale_credential_days:
                old.append({"AccessKeyId": key.get("access_key_id"), "AgeDays": days,
                            "Created": key.get("created_at")})
        return self.check(resource, bool(old), {"KeysOverThreshold": old, "ThresholdDays": ctx.stale_credential_days})


@register
class NoPasswordPolicy(Rule):
    metadata = RuleMetadata(
        rule_id="IAM-006",
        title="No account password policy is configured",
        severity=Severity.MEDIUM,
        service="IAM",
        category="Identity & Access",
        resource_type=rt.AWS_ACCOUNT,
        description="The account has no custom IAM password policy, so AWS defaults apply to IAM user passwords.",
        impact="Users may choose short, simple or reused passwords that are easy to guess or crack.",
        remediation="Configure an account password policy with a minimum length of 14 and reuse prevention of 24.",
        remediation_cli="aws iam update-account-password-policy --minimum-password-length 14 "
        "--password-reuse-prevention 24 --require-symbols --require-numbers "
        "--require-uppercase-characters --require-lowercase-characters",
        references=(_refs.IAM_PASSWORD_POLICY, _refs.CIS_AWS),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        if "password_policy" not in resource.properties:
            return None
        policy = resource.prop("password_policy")
        return self.check(resource, policy is None, {"PasswordPolicy": policy or "NoSuchEntity"})


@register
class WeakPasswordPolicy(Rule):
    metadata = RuleMetadata(
        rule_id="IAM-007",
        title="Password policy does not meet strength requirements",
        severity=Severity.MEDIUM,
        service="IAM",
        category="Identity & Access",
        resource_type=rt.AWS_ACCOUNT,
        description="The IAM password policy allows passwords shorter than 14 characters or permits "
        "recent password reuse.",
        impact="Weak password requirements make credential stuffing and offline cracking more effective.",
        remediation="Raise the minimum length to at least 14 and prevent reuse of the last 24 passwords.",
        remediation_cli="aws iam update-account-password-policy --minimum-password-length 14 --password-reuse-prevention 24",
        references=(_refs.IAM_PASSWORD_POLICY, _refs.CIS_AWS),
    )

    MIN_LENGTH = 14
    MIN_REUSE = 24

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        policy = resource.prop("password_policy")
        if not policy:
            return None  # covered by IAM-006
        weaknesses: list[str] = []
        length = policy.get("minimum_length") or 0
        reuse = policy.get("password_reuse_prevention") or 0
        if length < self.MIN_LENGTH:
            weaknesses.append(f"MinimumPasswordLength={length} (< {self.MIN_LENGTH})")
        if reuse < self.MIN_REUSE:
            weaknesses.append(f"PasswordReusePrevention={reuse} (< {self.MIN_REUSE})")
        return self.check(resource, bool(weaknesses), {"Weaknesses": weaknesses, "PasswordPolicy": policy})


@register
class FullAdminCustomerPolicy(Rule):
    metadata = RuleMetadata(
        rule_id="IAM-008",
        title="Customer managed policy grants full administrative privileges",
        severity=Severity.HIGH,
        service="IAM",
        category="Identity & Access",
        resource_type=rt.IAM_POLICY,
        description='An attached customer managed policy contains "Effect": "Allow", "Action": "*", "Resource": "*".',
        impact="Any principal with this policy can perform every action on every resource, including "
        "disabling logging and creating backdoor identities.",
        remediation="Replace the wildcard statement with the specific actions and resources the "
        "workload requires. Use IAM Access Analyzer policy generation to derive them.",
        remediation_steps=(
            "Identify the principals this policy is attached to.",
            "Generate a least-privilege policy from CloudTrail activity with IAM Access Analyzer.",
            "Create a new policy version without the */* statement and set it as default.",
        ),
        references=(_refs.IAM_BEST_PRACTICES, _refs.CIS_AWS),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        if not resource.prop("attachment_count"):
            return None
        offending = [
            pol.summarize_statement(s)
            for s in pol.statements(resource.prop("document"))
            if pol.is_full_admin_statement(s)
        ]
        return self.check(
            resource,
            bool(offending),
            {"AdminStatements": offending, "AttachmentCount": resource.prop("attachment_count")},
        )


@register
class UserWithDirectAdmin(Rule):
    metadata = RuleMetadata(
        rule_id="IAM-009",
        title="IAM user has administrative privileges",
        severity=Severity.HIGH,
        service="IAM",
        category="Identity & Access",
        resource_type=rt.IAM_USER,
        description="An IAM user holds full administrative permissions through attached, inline or "
        "group policies.",
        impact="Long-lived user credentials with administrator rights are a high-value target; a single "
        "leak compromises the entire account.",
        remediation="Remove administrator policies from IAM users. Grant elevated access through roles "
        "that are assumed on demand with MFA.",
        references=(_refs.IAM_BEST_PRACTICES, _refs.CIS_AWS),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        sources = principal_admin_sources(resource)
        return self.check(resource, bool(sources), {"AdminPolicySources": sources})


@register
class PubliclyAssumableRole(Rule):
    metadata = RuleMetadata(
        rule_id="IAM-010",
        title="IAM role can be assumed by any AWS principal",
        severity=Severity.CRITICAL,
        service="IAM",
        category="Identity & Access",
        resource_type=rt.IAM_ROLE,
        description='The role trust policy allows "Principal": {"AWS": "*"} without a condition that '
        "restricts the calling account or organization.",
        impact="Any authenticated AWS identity in any account can assume the role and inherit its permissions.",
        remediation="Restrict the trust policy to specific account or role ARNs, or add an "
        "aws:PrincipalOrgID / sts:ExternalId condition.",
        remediation_cli="aws iam update-assume-role-policy --role-name <role> --policy-document file://trust.json",
        references=(_refs.IAM_CONFUSED_DEPUTY, _refs.AWS_SECURITY_HUB_CONTROLS),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        trust = resource.prop("trust_policy")
        public = []
        for statement in pol.allow_statements(trust):
            if pol.principal_is_wildcard(statement.get("Principal")) and not (
                pol.has_restricting_condition(statement)
                or pol.statement_has_condition_key(statement, "sts:ExternalId")
            ):
                public.append(pol.summarize_statement(statement))
        return self.check(resource, bool(public), {"PublicTrustStatements": public})


@register
class CrossAccountTrustWithoutExternalId(Rule):
    metadata = RuleMetadata(
        rule_id="IAM-011",
        title="Cross-account role trust lacks an external ID condition",
        severity=Severity.MEDIUM,
        service="IAM",
        category="Identity & Access",
        resource_type=rt.IAM_ROLE,
        description="The role trusts principals in another AWS account but does not require sts:ExternalId.",
        impact="Third parties that serve many customers can be tricked into using their access against "
        "this account (confused deputy).",
        remediation="Add a StringEquals condition on sts:ExternalId with a unique value agreed with the third party.",
        references=(_refs.IAM_CONFUSED_DEPUTY,),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        trust = resource.prop("trust_policy")
        externals = pol.external_principals(trust, resource.account_id)
        if not externals:
            return None
        unprotected = []
        for statement in pol.allow_statements(trust):
            stmt_externals = pol.external_principals({"Statement": [statement]}, resource.account_id)
            if stmt_externals and not (
                pol.statement_has_condition_key(statement, "sts:ExternalId")
                or pol.statement_has_condition_key(statement, "aws:PrincipalOrgID")
            ):
                unprotected.extend(stmt_externals)
        return self.check(resource, bool(unprotected), {"TrustedExternalPrincipals": unprotected or externals})


@register
class UnusedIamUser(Rule):
    metadata = RuleMetadata(
        rule_id="IAM-012",
        title="IAM user inactive for 90+ days",
        severity=Severity.LOW,
        service="IAM",
        category="Identity & Access",
        resource_type=rt.IAM_USER,
        description="Neither the console password nor any access key of this user has been used within "
        "the inactivity window.",
        impact="Orphaned identities often belong to former staff or retired systems and are a common "
        "persistence vector.",
        remediation="Confirm the user is no longer needed, then remove its credentials and delete the user.",
        references=(_refs.IAM_BEST_PRACTICES, _refs.CIS_AWS),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        created_age = age_days(resource.prop("created_at"), ctx.now)
        if created_age is not None and created_age < ctx.unused_user_days:
            return None  # too new to judge
        activity = [resource.prop("password_last_used")] + [
            k.get("last_used_at") for k in resource.prop("access_keys", []) or []
        ]
        ages = [a for a in (age_days(ts, ctx.now) for ts in activity) if a is not None]
        last_activity_days = min(ages) if ages else None
        inactive = last_activity_days is None or last_activity_days >= ctx.unused_user_days
        return self.check(
            resource,
            inactive,
            {"DaysSinceLastActivity": last_activity_days if last_activity_days is not None else "never",
             "ThresholdDays": ctx.unused_user_days},
        )


@register
class PrivilegedUserWithoutMfa(Rule):
    metadata = RuleMetadata(
        rule_id="IAM-013",
        title="Administrator user without MFA",
        severity=Severity.CRITICAL,
        service="IAM",
        category="Identity & Access",
        resource_type=rt.IAM_USER,
        description="An IAM user with full administrative permissions can sign in to the console without MFA.",
        impact="A single stolen password grants complete, interactive control of the account.",
        remediation="Enable MFA immediately, then migrate administrative access to MFA-protected roles.",
        references=(_refs.IAM_BEST_PRACTICES,),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        sources = principal_admin_sources(resource)
        if not sources:
            return None
        weak = _console_user(resource) and not resource.prop("mfa_enabled")
        return self.check(
            resource,
            weak,
            {"AdminPolicySources": sources, "PasswordEnabled": _console_user(resource),
             "MFAEnabled": bool(resource.prop("mfa_enabled"))},
        )


@register
class MultipleActiveAccessKeys(Rule):
    metadata = RuleMetadata(
        rule_id="IAM-014",
        title="IAM user has more than one active access key",
        severity=Severity.LOW,
        service="IAM",
        category="Identity & Access",
        resource_type=rt.IAM_USER,
        description="Two active access keys exist for the same user outside of a rotation window.",
        impact="A forgotten second key doubles credential exposure and is frequently left behind after rotation.",
        remediation="Keep at most one active key per user; deactivate the unused key.",
        references=(_refs.IAM_ACCESS_KEYS, _refs.CIS_AWS),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        active = [k.get("access_key_id") for k in resource.prop("access_keys", []) or [] if k.get("status") == "Active"]
        if not active:
            return None
        return self.check(resource, len(active) > 1, {"ActiveAccessKeys": active})


@register
class PrivilegeEscalationPolicy(Rule):
    metadata = RuleMetadata(
        rule_id="IAM-015",
        title="Policy allows IAM privilege escalation",
        severity=Severity.HIGH,
        service="IAM",
        category="Identity & Access",
        resource_type=rt.IAM_POLICY,
        description="An attached customer managed policy grants IAM actions on all resources that let a "
        "principal raise its own privileges (for example iam:CreatePolicyVersion or iam:PassRole).",
        impact="A principal holding this policy can escalate to administrator even though the policy "
        "does not appear to grant admin rights directly.",
        remediation="Scope these IAM actions to specific resource ARNs, or remove them and delegate IAM "
        "changes to a controlled pipeline. Consider permission boundaries.",
        references=(_refs.IAM_BEST_PRACTICES,),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        if not resource.prop("attachment_count"):
            return None
        doc = resource.prop("document")
        if pol.grants_full_admin(doc):
            return None  # IAM-008 already reports the stronger condition
        actions = pol.escalation_actions(doc)
        return self.check(resource, bool(actions), {"EscalationActions": actions, "Resource": "*"})
