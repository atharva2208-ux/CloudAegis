"""Scan engine orchestration: discovery, evaluation, resilience, progress, cancellation."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterator

import pytest

from cloudaegis_engine.engine import ScanCancelled, ScanEngine
from cloudaegis_engine.models import Resource, RuleMetadata, Severity
from cloudaegis_engine.providers import PROVIDERS, ProviderError, create_provider
from cloudaegis_engine.providers.base import CloudProvider, ConnectionResult, ServiceAccessError
from cloudaegis_engine.providers.demo import DemoProvider
from cloudaegis_engine.rules.base import Rule
from cloudaegis_engine.rules.registry import RuleRegistry, default_registry

NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)
REGIONS = ["us-east-1", "eu-west-1"]


def demo(maturity: float = 0.5, scale: float = 0.2) -> DemoProvider:
    return DemoProvider(maturity=maturity, scale=scale, now=NOW)


class FakeProvider(CloudProvider):
    """Minimal provider: one service works, one is denied."""

    provider_name = "fake"

    def validate_connection(self) -> ConnectionResult:
        return ConnectionResult(ok=True, account_id="111122223333")

    def account_id(self) -> str:
        return "111122223333"

    def supported_services(self) -> list[str]:
        return ["Widgets", "Denied"]

    def discover_service(self, service: str, regions: list[str]) -> Iterator[Resource]:
        if service == "Denied":
            raise ServiceAccessError(service, "AccessDenied — check the audit role's permissions")
        for i in range(3):
            yield Resource(uid=f"w-{i}", resource_type="test.widget", service="Widgets", name=f"w{i}",
                           region=regions[0], account_id="111122223333", properties={"ok": i != 1})


def _meta(rule_id: str) -> RuleMetadata:
    return RuleMetadata(rule_id=rule_id, title="t", severity=Severity.HIGH, service="Widgets", category="c",
                        resource_type="test.widget", description="d", impact="i", remediation="r")


class WidgetOk(Rule):
    metadata = _meta("W-001")

    def evaluate(self, resource, ctx):
        return self.check(resource, not resource.prop("ok"), {"ok": resource.prop("ok")})


class WidgetBroken(Rule):
    metadata = _meta("W-002")

    def evaluate(self, resource, ctx):
        raise RuntimeError("bug in rule")


def test_full_demo_scan_produces_findings_and_stats():
    output = ScanEngine(demo(), now=NOW).run(REGIONS)
    assert len(output.inventory) > 100
    assert output.failures, "a partially mature estate must have findings"
    assert not output.service_errors and not output.rule_errors
    evaluated = sum(s.evaluated for s in output.rule_stats.values())
    assert evaluated == len(output.results)
    assert all(r.resource_uid in {res.uid for res in output.inventory} for r in output.results)
    assert set(output.exposure) == {r.uid for r in output.inventory}


def test_scan_is_deterministic():
    a = ScanEngine(demo(), now=NOW).run(REGIONS)
    b = ScanEngine(demo(), now=NOW).run(REGIONS)
    key = lambda out: sorted((r.rule_id, r.resource_uid, r.outcome.value) for r in out.results)  # noqa: E731
    assert key(a) == key(b)


def test_higher_maturity_mostly_fixes_findings():
    low = ScanEngine(demo(maturity=0.2), now=NOW).run(REGIONS)
    high = ScanEngine(demo(maturity=0.9), now=NOW).run(REGIONS)
    fail = lambda out: {(r.rule_id, r.resource_uid) for r in out.failures}  # noqa: E731
    assert len(fail(high)) < 0.6 * len(fail(low))
    drift = fail(high) - fail(low)
    assert len(drift) <= 0.05 * len(fail(high)), "only a little drift may introduce new findings"


def test_resource_identities_are_stable_across_maturity():
    regions = ["ap-south-1", "eu-west-1", "us-east-1", "us-west-2"]
    low, high = demo(maturity=0.2, scale=1.0), demo(maturity=0.9, scale=1.0)
    for service in low.supported_services():
        assert {r.uid for r in low.discover_service(service, regions)} == {
            r.uid for r in high.discover_service(service, regions)
        }, service


def test_service_selection_limits_discovery():
    output = ScanEngine(demo(), now=NOW).run(REGIONS, services=["S3"])
    assert {r.service for r in output.inventory} == {"S3"}


def test_region_selection_limits_regional_resources():
    output = ScanEngine(demo(), now=NOW).run(["eu-west-1"], services=["EC2"])
    assert {r.region for r in output.inventory} <= {"eu-west-1", "global"}


def test_denied_service_is_reported_not_fatal():
    registry = RuleRegistry([WidgetOk()])
    output = ScanEngine(FakeProvider(), registry=registry).run(["us-east-1"])
    assert output.service_errors == {"Denied": "AccessDenied — check the audit role's permissions"}
    assert len(output.inventory) == 3
    assert [r.resource_uid for r in output.failures] == ["w-1"]


def test_broken_rule_does_not_abort_scan():
    registry = RuleRegistry([WidgetOk(), WidgetBroken()])
    output = ScanEngine(FakeProvider(), registry=registry).run(["us-east-1"])
    assert output.rule_errors == {"W-002": "RuntimeError"}
    assert len(output.results) == 3


def test_progress_reaches_completion():
    snapshots = []
    ScanEngine(demo(), now=NOW).run(REGIONS, progress=snapshots.append)
    assert snapshots[0].phase == "discovery"
    last = snapshots[-1]
    assert last.phase == "completed"
    assert all(s.status == "completed" and s.percent == 100 for s in last.services)
    assert last.assets_analyzed == last.assets_discovered


def test_failed_service_progress_marks_error():
    snapshots = []
    ScanEngine(FakeProvider(), registry=RuleRegistry([WidgetOk()])).run(["us-east-1"], progress=snapshots.append)
    denied = next(s for s in snapshots[-1].services if s.service == "Denied")
    assert denied.status == "failed" and "AccessDenied" in denied.error


def test_cancellation_stops_scan():
    calls = {"n": 0}

    def should_cancel() -> bool:
        calls["n"] += 1
        return calls["n"] > 2

    with pytest.raises(ScanCancelled):
        ScanEngine(demo(), now=NOW).run(REGIONS, should_cancel=should_cancel)


def test_disabled_rules_are_not_evaluated():
    registry = default_registry().without(["S3-001", "S3-002"])
    output = ScanEngine(demo(), registry=registry, now=NOW).run(REGIONS, services=["S3"])
    assert not {"S3-001", "S3-002"} & {r.rule_id for r in output.results}


def test_thresholds_flow_into_rule_context():
    strict = ScanEngine(demo(), now=NOW, context_options={"stale_credential_days": 30}).run(REGIONS, services=["IAM"])
    lenient = ScanEngine(demo(), now=NOW, context_options={"stale_credential_days": 365}).run(REGIONS, services=["IAM"])
    count = lambda out: sum(1 for r in out.failures if r.rule_id == "IAM-005")  # noqa: E731
    assert count(strict) >= count(lenient)


def test_summarize_reports_score_and_compliance():
    engine = ScanEngine(demo(), now=NOW)
    summary = engine.summarize(engine.run(REGIONS))
    assert 0 <= summary["score"]["score"] <= 100
    assert {c["key"] for c in summary["compliance"]} >= {"cis-aws", "nist-csf", "aws-wa-security"}


def test_provider_factory():
    assert set(PROVIDERS) >= {"aws", "demo"}
    assert isinstance(create_provider("demo", {"scale": 0.1}), DemoProvider)
    with pytest.raises(ProviderError):
        create_provider("azure-not-yet", {})


def test_demo_provider_validates_and_is_labelled_simulated():
    result = demo().validate_connection()
    assert result.ok and result.regions
    assert "Simulated" in result.message


def test_demo_estate_has_unique_resource_ids():
    regions = ["ap-south-1", "eu-west-1", "us-east-1", "us-west-2"]
    for scale in (1.0, 0.2):
        provider = demo(scale=scale)
        uids = [r.uid for s in provider.supported_services() for r in provider.discover_service(s, regions)]
        assert len(uids) == len(set(uids))


class DuplicatingProvider(FakeProvider):
    def supported_services(self) -> list[str]:
        return ["Widgets"]

    def discover_service(self, service, regions):
        yield from super().discover_service(service, regions)
        yield from super().discover_service(service, regions)  # e.g. a paginator replaying a page


def test_duplicate_resources_are_evaluated_once():
    output = ScanEngine(DuplicatingProvider(), registry=RuleRegistry([WidgetOk()])).run(["us-east-1"])
    assert len(output.inventory) == 3
    assert len(output.results) == 3
