"""AWS provider adapter (boto3)."""

from __future__ import annotations

from typing import Any, Iterator

from botocore.exceptions import BotoCoreError, ClientError

from cloudaegis_engine.models import Resource
from cloudaegis_engine.providers.aws.collectors import CollectorContext, collectors
from cloudaegis_engine.providers.aws.collectors._util import ACCESS_DENIED_CODES, error_code
from cloudaegis_engine.providers.aws.session import BOTO_CONFIG, build_session
from cloudaegis_engine.providers.base import CloudProvider, ConnectionResult, ServiceAccessError
from cloudaegis_engine.resource_types import SERVICE_ORDER


class AWSProvider(CloudProvider):
    provider_name = "aws"

    def __init__(self, auth: dict[str, Any], expected_account_id: str | None = None,
                 default_region: str = "us-east-1") -> None:
        self._auth = auth
        self._expected_account = expected_account_id
        self._default_region = default_region
        self._session = None
        self._account_id: str | None = expected_account_id
        self._partition = "aws"

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> "AWSProvider":
        return cls(
            auth=config.get("auth", {}),
            expected_account_id=config.get("account_id"),
            default_region=config.get("default_region", "us-east-1"),
        )

    @property
    def session(self):
        if self._session is None:
            self._session = build_session(self._auth, self._default_region)
        return self._session

    def validate_connection(self) -> ConnectionResult:
        try:
            identity = self.session.client("sts", config=BOTO_CONFIG).get_caller_identity()
        except (ClientError, BotoCoreError) as exc:
            return ConnectionResult(ok=False, message=f"Unable to authenticate: {error_code(exc)}")
        except Exception as exc:  # provider errors (bad config) carry safe messages
            return ConnectionResult(ok=False, message=str(exc))
        account = identity["Account"]
        arn = identity["Arn"]
        self._partition = arn.split(":")[1] if arn.startswith("arn:") else "aws"
        if self._expected_account and account != self._expected_account:
            return ConnectionResult(ok=False, account_id=account, principal_arn=arn,
                                    message=f"Credentials belong to account {account}, expected {self._expected_account}")
        self._account_id = account
        warnings: list[str] = []
        try:
            regions = sorted(
                r["RegionName"]
                for r in self.session.client("ec2", region_name=self._default_region, config=BOTO_CONFIG)
                .describe_regions(AllRegions=False)["Regions"]
            )
        except (ClientError, BotoCoreError) as exc:
            regions = [self._default_region]
            warnings.append(f"Region discovery failed ({error_code(exc)}); defaulting to {self._default_region}")
        return ConnectionResult(ok=True, account_id=account, principal_arn=arn, regions=regions,
                                message="Connection verified", warnings=warnings)

    def account_id(self) -> str:
        if self._account_id is None:
            result = self.validate_connection()
            if not result.ok:
                raise ServiceAccessError("STS", result.message)
        return self._account_id  # type: ignore[return-value]

    def supported_services(self) -> list[str]:
        available = collectors()
        return [s for s in SERVICE_ORDER if s in available]

    def discover_service(self, service: str, regions: list[str]) -> Iterator[Resource]:
        collector = collectors().get(service)
        if collector is None:
            return iter(())
        ctx = CollectorContext(session=self.session, account_id=self.account_id(), regions=regions,
                               partition=self._partition)
        return self._guard(service, collector(ctx))

    @staticmethod
    def _guard(service: str, iterator: Iterator[Resource]) -> Iterator[Resource]:
        try:
            yield from iterator
        except ClientError as exc:
            code = error_code(exc)
            hint = " — check the audit role's permissions" if code in ACCESS_DENIED_CODES else ""
            raise ServiceAccessError(service, f"{code}{hint}") from None
        except BotoCoreError as exc:
            raise ServiceAccessError(service, type(exc).__name__) from None
