"""Scan orchestration: discover → evaluate → summarise.

The engine is synchronous and side-effect free. The web backend runs it
in a background worker and persists :class:`ScanOutput`.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Iterable

from cloudaegis_engine import posture
from cloudaegis_engine.compliance import RuleStats, evaluate_all
from cloudaegis_engine.models import Inventory, Resource, RuleResult
from cloudaegis_engine.providers.base import CloudProvider, ServiceAccessError
from cloudaegis_engine.rules.base import RuleContext
from cloudaegis_engine.rules.registry import RuleRegistry, default_registry
from cloudaegis_engine.scoring import calculate_security_score

log = logging.getLogger("cloudaegis.engine")

# Phase weights used to turn discovery + analysis into one percentage per service.
DISCOVERY_SHARE = 60


@dataclass
class ServiceProgress:
    service: str
    status: str = "pending"  # pending | discovering | discovered | analyzing | completed | failed
    percent: int = 0
    resources: int = 0
    findings: int = 0
    error: str | None = None

    def as_dict(self) -> dict:
        return {
            "service": self.service,
            "status": self.status,
            "percent": self.percent,
            "resources": self.resources,
            "findings": self.findings,
            "error": self.error,
        }


@dataclass
class ProgressSnapshot:
    phase: str
    services: list[ServiceProgress]
    assets_discovered: int
    assets_analyzed: int

    def as_dict(self) -> dict:
        return {
            "phase": self.phase,
            "services": [s.as_dict() for s in self.services],
            "assets_discovered": self.assets_discovered,
            "assets_analyzed": self.assets_analyzed,
        }


ProgressCallback = Callable[[ProgressSnapshot], None]


class ScanCancelled(Exception):
    pass


@dataclass
class ScanOutput:
    account_id: str
    started_at: datetime
    finished_at: datetime
    inventory: Inventory
    results: list[RuleResult]
    rule_stats: dict[str, RuleStats]
    service_errors: dict[str, str]
    rule_errors: dict[str, str]
    exposure: dict[str, bool] = field(default_factory=dict)
    encryption: dict[str, str] = field(default_factory=dict)

    @property
    def failures(self) -> list[RuleResult]:
        return [r for r in self.results if r.failed]

    @property
    def duration_seconds(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()


class ScanEngine:
    def __init__(
        self,
        provider: CloudProvider,
        registry: RuleRegistry | None = None,
        context_options: dict | None = None,
        now: datetime | None = None,
    ) -> None:
        self.provider = provider
        self.registry = registry or default_registry()
        self.context_options = context_options or {}
        self.now = now

    def run(
        self,
        regions: list[str],
        services: Iterable[str] | None = None,
        progress: ProgressCallback | None = None,
        should_cancel: Callable[[], bool] | None = None,
    ) -> ScanOutput:
        started = datetime.now(timezone.utc)
        selected = [s for s in self.provider.supported_services() if services is None or s in set(services)]
        tracker = {s: ServiceProgress(service=s) for s in selected}
        inventory = Inventory()
        per_service: dict[str, list[Resource]] = defaultdict(list)
        service_errors: dict[str, str] = {}
        analyzed = 0

        def emit(phase: str) -> None:
            if progress:
                progress(ProgressSnapshot(phase, list(tracker.values()), len(inventory), analyzed))

        def check_cancel() -> None:
            if should_cancel and should_cancel():
                raise ScanCancelled()

        account_id = self.provider.account_id()

        # 1. Discovery ---------------------------------------------------------
        emit("discovery")
        for service in selected:
            check_cancel()
            state = tracker[service]
            state.status = "discovering"
            state.percent = 5
            emit("discovery")
            try:
                last_emit = time.monotonic()
                for resource in self.provider.discover_service(service, regions):
                    if inventory.get(resource.uid) is not None:
                        # Providers may surface the same resource twice (e.g. paginated
                        # APIs, global resources); evaluate each resource exactly once.
                        log.debug("duplicate_resource_skipped", extra={"uid": resource.uid})
                        continue
                    inventory.add(resource)
                    per_service[service].append(resource)
                    state.resources += 1
                    if time.monotonic() - last_emit > 0.5:
                        state.percent = min(DISCOVERY_SHARE - 5, state.percent + 5)
                        emit("discovery")
                        last_emit = time.monotonic()
                        check_cancel()
                state.percent = DISCOVERY_SHARE
                state.status = "discovered"
            except ServiceAccessError as exc:
                state.status = "failed"
                state.error = exc.message
                service_errors[service] = exc.message
                log.warning("service_discovery_failed", extra={"service": service, "error": exc.message})
            emit("discovery")

        # 2. Evaluation --------------------------------------------------------
        ctx = RuleContext(inventory=inventory, **({"now": self.now} if self.now else {}), **self.context_options)
        results: list[RuleResult] = []
        stats: dict[str, RuleStats] = {r.rule_id: RuleStats() for r in self.registry.all()}
        rule_errors: dict[str, str] = {}
        for service in selected:
            state = tracker[service]
            if state.status == "failed":
                continue
            check_cancel()
            state.status = "analyzing"
            emit("analysis")
            resources = per_service[service]
            total = max(1, len(resources))
            for index, resource in enumerate(resources, start=1):
                for rule in self.registry.for_type(resource.resource_type):
                    try:
                        result = rule.evaluate(resource, ctx)
                    except Exception as exc:  # a broken rule must not abort the scan
                        rule_errors[rule.rule_id] = type(exc).__name__
                        log.exception("rule_failed", extra={"rule_id": rule.rule_id, "resource": resource.uid})
                        continue
                    if result is None:
                        continue
                    results.append(result)
                    previous = stats[rule.rule_id]
                    stats[rule.rule_id] = RuleStats(
                        evaluated=previous.evaluated + 1,
                        failed=previous.failed + (1 if result.failed else 0),
                    )
                    if result.failed:
                        state.findings += 1
                analyzed += 1
                if index % 50 == 0 or index == total:
                    state.percent = DISCOVERY_SHARE + int((100 - DISCOVERY_SHARE) * index / total)
                    emit("analysis")
            state.status = "completed"
            state.percent = 100
            emit("analysis")

        exposure = {r.uid: posture.is_publicly_exposed(r, inventory) for r in inventory}
        encryption = {r.uid: posture.encryption_status(r) for r in inventory}
        emit("completed")
        return ScanOutput(
            account_id=account_id,
            started_at=started,
            finished_at=datetime.now(timezone.utc),
            inventory=inventory,
            results=results,
            rule_stats=stats,
            service_errors=service_errors,
            rule_errors=rule_errors,
            exposure=exposure,
            encryption=encryption,
        )

    # Convenience for quick, unpersisted evaluations (CLI, tests).
    def summarize(self, output: ScanOutput) -> dict:
        severity = {r.rule_id: r.metadata.severity for r in self.registry.all()}
        score = calculate_security_score((severity[r.rule_id], r.failed) for r in output.results)
        return {
            "account_id": output.account_id,
            "assets": len(output.inventory),
            "findings": len(output.failures),
            "score": score.as_dict(),
            "compliance": [f.as_dict() for f in evaluate_all(output.rule_stats)],
            "service_errors": output.service_errors,
        }
