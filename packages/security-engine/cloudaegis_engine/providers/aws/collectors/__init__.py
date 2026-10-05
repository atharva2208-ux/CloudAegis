"""Per-service AWS collectors.

Each collector module exposes ``collect(ctx: CollectorContext)`` which
yields normalized resources. Registering a new AWS service is a matter of
adding a module and an entry in :data:`COLLECTORS`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterator

import boto3

from cloudaegis_engine.models import Resource
from cloudaegis_engine.providers.aws.session import BOTO_CONFIG


@dataclass
class CollectorContext:
    session: boto3.Session
    account_id: str
    regions: list[str]
    partition: str = "aws"
    _clients: dict[tuple[str, str], Any] = field(default_factory=dict)

    def client(self, service: str, region: str | None = None) -> Any:
        region = region or (self.regions[0] if self.regions else "us-east-1")
        key = (service, region)
        if key not in self._clients:
            self._clients[key] = self.session.client(service, region_name=region, config=BOTO_CONFIG)
        return self._clients[key]

    def arn(self, service: str, region: str, resource: str) -> str:
        return f"arn:{self.partition}:{service}:{region}:{self.account_id}:{resource}"


Collector = Callable[[CollectorContext], Iterator[Resource]]


def _load() -> dict[str, Collector]:
    from cloudaegis_engine.providers.aws.collectors import (
        cloudtrail,
        ec2,
        ecr,
        iam,
        kms,
        lambda_,
        rds,
        s3,
        secretsmanager,
        vpc,
    )

    return {
        "IAM": iam.collect,
        "S3": s3.collect,
        "EC2": ec2.collect,
        "VPC": vpc.collect,
        "RDS": rds.collect,
        "CloudTrail": cloudtrail.collect,
        "Lambda": lambda_.collect,
        "ECR": ecr.collect,
        "KMS": kms.collect,
        "Secrets Manager": secretsmanager.collect,
    }


COLLECTORS: dict[str, Collector] = {}


def collectors() -> dict[str, Collector]:
    if not COLLECTORS:
        COLLECTORS.update(_load())
    return COLLECTORS
