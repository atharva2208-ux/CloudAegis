"""ECR repository discovery."""

from __future__ import annotations

from typing import Iterator

from cloudaegis_engine import resource_types as rt
from cloudaegis_engine.models import Resource
from cloudaegis_engine.providers.aws.collectors import CollectorContext
from cloudaegis_engine.providers.aws.collectors._util import call, iso, policy_doc
from cloudaegis_engine.providers.aws.collectors.ec2 import _paginate


def collect(ctx: CollectorContext) -> Iterator[Resource]:
    for region in ctx.regions:
        ecr = ctx.client("ecr", region)
        for repo in _paginate(ecr, "describe_repositories", "repositories"):
            name = repo["repositoryName"]
            policy = call(ecr.get_repository_policy, repositoryName=name,
                          missing=("RepositoryPolicyNotFoundException",))
            enc = repo.get("encryptionConfiguration") or {}
            yield Resource(
                uid=repo["repositoryArn"],
                resource_type=rt.ECR_REPOSITORY,
                service="ECR",
                name=name,
                region=region,
                account_id=ctx.account_id,
                properties={
                    "repository_name": name,
                    "repository_uri": repo.get("repositoryUri"),
                    "scan_on_push": bool((repo.get("imageScanningConfiguration") or {}).get("scanOnPush")),
                    "image_tag_mutability": repo.get("imageTagMutability", "MUTABLE"),
                    "encryption_type": enc.get("encryptionType", "AES256"),
                    "kms_key": enc.get("kmsKey"),
                    "repository_policy": policy_doc(policy.get("policyText")) if policy else None,
                    "created_at": iso(repo.get("createdAt")),
                },
            )
