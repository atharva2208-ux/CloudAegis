"""Remediation guidance generation.

CloudAegis never changes cloud infrastructure. This module only renders
guidance: ordered steps plus an *example* CLI command with placeholders
filled from the affected resource, for an operator to review and run.
"""

from __future__ import annotations

from dataclasses import dataclass

from cloudaegis_engine.models import Resource, RuleMetadata


@dataclass(frozen=True)
class RemediationPlan:
    summary: str
    steps: list[str]
    cli_example: str | None
    automated: bool = False  # always False: remediation is never applied automatically

    def as_dict(self) -> dict:
        return {
            "summary": self.summary,
            "steps": self.steps,
            "cli_example": self.cli_example,
            "automated": self.automated,
        }


def _placeholders(resource: Resource) -> dict[str, str]:
    p = resource.properties
    values = {
        "<bucket>": p.get("bucket_name"),
        "<sg-id>": p.get("group_id"),
        "<user>": p.get("user_name"),
        "<role>": p.get("role_name"),
        "<fn>": p.get("function_name"),
        "<repo>": p.get("repository_name"),
        "<trail>": p.get("trail_name"),
        "<key-id>": p.get("key_id"),
        "<vpc-id>": p.get("vpc_id"),
        "<subnet-id>": p.get("subnet_id"),
        "<account-id>": resource.account_id,
        "<region>": resource.region,
        "<id>": p.get("db_instance_id") or p.get("instance_id") or p.get("secret_name"),
    }
    return {k: str(v) for k, v in values.items() if v}


def build_plan(metadata: RuleMetadata, resource: Resource | None = None) -> RemediationPlan:
    steps = list(metadata.remediation_steps) or [metadata.remediation]
    cli = metadata.remediation_cli
    if cli and resource is not None:
        for placeholder, value in _placeholders(resource).items():
            cli = cli.replace(placeholder, value)
    if cli and resource is not None and resource.region not in ("global", "") and "--region" not in cli:
        cli = f"{cli} --region {resource.region}"
    return RemediationPlan(summary=metadata.remediation, steps=steps, cli_example=cli)
