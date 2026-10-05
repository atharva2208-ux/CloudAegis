"""Simulated AWS environment for demos, development and recruiters.

The demo provider implements the same :class:`CloudProvider` interface as
the real AWS adapter and emits the same normalized resource shapes. The
security engine, scoring and compliance evaluation run unmodified on this
data — findings are *computed*, not hard-coded.

Generation is deterministic: the same ``seed`` always yields the same
estate. ``maturity`` (0.0–1.0) controls how many resources are
misconfigured. Resource identities are stable across maturity levels and
raising maturity mostly *fixes* resources, which produces a believable
remediation trend; a small amount of configuration drift still introduces
new findings between scans, as it does in real estates.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Iterator

from cloudaegis_engine.models import Resource
from cloudaegis_engine.providers.base import CloudProvider, ConnectionResult
from cloudaegis_engine.providers.demo.generator import DEMO_REGIONS, DemoEstate
from cloudaegis_engine.resource_types import SERVICE_ORDER

DEMO_ACCOUNT_ID = "481516234200"


class DemoProvider(CloudProvider):
    provider_name = "demo"

    def __init__(self, account_id: str = DEMO_ACCOUNT_ID, seed: int = 7, maturity: float = 0.55,
                 now: datetime | None = None, scale: float = 1.0, pace_seconds: float = 0.0) -> None:
        self._account_id = account_id
        # Optional simulated API latency so live scan progress is observable in demos.
        self._pace = max(0.0, pace_seconds)
        self._estate = DemoEstate(account_id=account_id, seed=seed, maturity=maturity,
                                  now=now or datetime.now(timezone.utc), scale=scale)

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> "DemoProvider":
        now = config.get("now")
        if isinstance(now, str):
            now = datetime.fromisoformat(now)
        return cls(
            account_id=config.get("account_id", DEMO_ACCOUNT_ID),
            seed=int(config.get("seed", 7)),
            maturity=float(config.get("maturity", 0.55)),
            now=now,
            scale=float(config.get("scale", 1.0)),
            pace_seconds=float(config.get("pace_seconds", 0.0)),
        )

    def validate_connection(self) -> ConnectionResult:
        return ConnectionResult(
            ok=True,
            account_id=self._account_id,
            principal_arn=f"arn:aws:sts::{self._account_id}:assumed-role/CloudAegisAudit/demo",
            regions=list(DEMO_REGIONS),
            message="Simulated environment — no AWS API calls are made",
        )

    def account_id(self) -> str:
        return self._account_id

    def supported_services(self) -> list[str]:
        return list(SERVICE_ORDER)

    def discover_service(self, service: str, regions: list[str]) -> Iterator[Resource]:
        wanted = set(regions) | {"global"}
        resources = [r for r in self._estate.service(service) if r.region in wanted]
        delay = self._pace / max(1, self._total()) if self._pace else 0.0
        for resource in resources:
            if delay:
                time.sleep(delay)
            yield resource

    def _total(self) -> int:
        return sum(len(self._estate.service(s)) for s in SERVICE_ORDER)
