"""Compliance catalog integrity and control evaluation semantics."""

from __future__ import annotations

import pytest

from cloudaegis_engine.compliance import (
    FRAMEWORKS,
    Control,
    Framework,
    RuleStats,
    evaluate_all,
    evaluate_framework,
    get_framework,
)
from cloudaegis_engine.rules import default_registry

TOY = Framework(
    key="toy",
    name="Toy Framework",
    short_name="Toy",
    version="1",
    description="test",
    controls=(
        Control("T1", "Encrypt data", "", ("R-1", "R-2"), "Data"),
        Control("T2", "Log things", "", ("R-3",), "Logging"),
        Control("T3", "Unused service", "", ("R-4",), "Other"),
    ),
)


def test_required_frameworks_present():
    keys = {f.key for f in FRAMEWORKS}
    assert {"cis-aws", "aws-wa-security", "nist-csf"} <= keys


@pytest.mark.parametrize("framework", FRAMEWORKS, ids=lambda f: f.key)
def test_catalog_references_only_real_rules(framework):
    registry = default_registry()
    unknown = {r for r in framework.rule_ids() if r not in registry}
    assert not unknown, f"{framework.key} maps unknown rules: {sorted(unknown)}"


@pytest.mark.parametrize("framework", FRAMEWORKS, ids=lambda f: f.key)
def test_control_ids_are_unique_and_described(framework):
    ids = [c.control_id for c in framework.controls]
    assert len(ids) == len(set(ids))
    for control in framework.controls:
        assert control.title and control.section and control.rule_ids


def test_every_rule_maps_to_some_framework():
    mapped = set().union(*(f.rule_ids() for f in FRAMEWORKS))
    unmapped = [r.rule_id for r in default_registry().all() if r.rule_id not in mapped]
    assert not unmapped


def test_get_framework_lookup():
    assert get_framework("cis-aws").short_name == "CIS AWS"
    assert get_framework("does-not-exist") is None


def test_control_statuses():
    stats = {"R-1": RuleStats(evaluated=10, failed=0), "R-2": RuleStats(evaluated=5, failed=1), "R-3": RuleStats(4, 0)}
    result = evaluate_framework(TOY, stats)
    by_id = {c.control_id: c for c in result.controls}
    assert by_id["T1"].status == "FAIL"
    assert by_id["T1"].failing_rules == ["R-2"]
    assert by_id["T1"].evaluated_resources == 15 and by_id["T1"].failed_resources == 1
    assert by_id["T2"].status == "PASS"
    assert by_id["T3"].status == "NOT_APPLICABLE"
    assert (result.passed, result.failed, result.not_applicable) == (1, 1, 1)


def test_score_is_mean_resource_compliance_of_assessed_controls():
    stats = {"R-1": RuleStats(10, 0), "R-2": RuleStats(10, 5), "R-3": RuleStats(4, 0)}
    result = evaluate_framework(TOY, stats)
    # T1: 1 - 5/20 = 0.75 ; T2: 1.0 ; T3 not applicable (excluded)
    assert result.score == pytest.approx(87.5)


def test_nothing_assessed_scores_100_and_all_not_applicable():
    result = evaluate_framework(TOY, {})
    assert result.score == 100.0
    assert result.not_applicable == 3


def test_evaluate_all_covers_every_framework():
    results = evaluate_all({})
    assert [r.key for r in results] == [f.key for f in FRAMEWORKS]
    assert all(r.as_dict()["total"] == len(get_framework(r.key).controls) for r in results)


def test_new_framework_needs_no_engine_change():
    """Adding a framework is pure data: evaluation works on any Framework instance."""
    custom = Framework("pci", "PCI DSS", "PCI", "4.0", "", (Control("3.5", "Protect stored data", "", ("S3-004",), "Data"),))
    assert evaluate_framework(custom, {"S3-004": RuleStats(3, 3)}).controls[0].status == "FAIL"
