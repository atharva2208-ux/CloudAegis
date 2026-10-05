"""Rule registry contract: every built-in rule is well formed and mapped to compliance."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from cloudaegis_engine import resource_types as rt
from cloudaegis_engine.compliance.catalog import FRAMEWORKS, controls_for_rule
from cloudaegis_engine.models import Severity
from cloudaegis_engine.rules.base import Rule
from cloudaegis_engine.rules.registry import RuleRegistry, default_registry, register

REGISTRY = default_registry()
RULES = REGISTRY.all()
RULE_IDS = [r.rule_id for r in RULES]
ID_PATTERN = re.compile(r"^[A-Z][A-Z0-9]{1,3}-\d{3}$")  # S3-001, EC2-004, IAM-012, LAM-006
PREFIX_SERVICE = {"IAM": "IAM", "S3": "S3", "EC2": "EC2", "VPC": "VPC", "RDS": "RDS", "CT": "CloudTrail",
                  "LAM": "Lambda", "ECR": "ECR", "KMS": "KMS", "SM": "Secrets Manager"}


def by_id(param):
    return pytest.mark.parametrize("rule", RULES, ids=RULE_IDS)(param)


def test_has_at_least_40_rules():
    assert len(REGISTRY) >= 40
    assert len(RULES) == len(REGISTRY)


def test_rule_ids_are_unique():
    assert len(set(RULE_IDS)) == len(RULE_IDS)


def test_every_builtin_service_has_rules():
    assert set(REGISTRY.services()) == set(PREFIX_SERVICE.values())


def test_default_registry_is_cached():
    assert default_registry() is REGISTRY


@by_id
def test_rule_id_format_and_prefix(rule):
    assert ID_PATTERN.match(rule.rule_id), rule.rule_id
    prefix = rule.rule_id.split("-")[0]
    assert PREFIX_SERVICE.get(prefix) == rule.metadata.service


@by_id
def test_rule_is_a_rule_instance(rule):
    assert isinstance(rule, Rule)
    assert rule.rule_id == rule.metadata.rule_id
    assert rule.resource_type == rule.metadata.resource_type


@by_id
def test_metadata_text_fields_are_populated(rule):
    m = rule.metadata
    for field in ("title", "description", "impact", "remediation", "category", "service"):
        value = getattr(m, field)
        assert isinstance(value, str) and value.strip(), f"{m.rule_id}.{field} is empty"
    assert all(step.strip() for step in m.remediation_steps)
    assert m.remediation_cli is None or m.remediation_cli.strip()


@by_id
def test_has_https_reference(rule):
    refs = rule.metadata.references
    assert any(ref.startswith("https://") for ref in refs), refs
    # Anything that looks like a link must be HTTPS.
    assert not any(ref.startswith("http://") for ref in refs)


@by_id
def test_severity_is_valid(rule):
    assert isinstance(rule.metadata.severity, Severity)
    assert rule.metadata.severity in Severity.ordered()


@by_id
def test_resource_type_is_known(rule):
    assert rule.metadata.resource_type in rt.SERVICE_OF


@by_id
def test_maps_to_a_compliance_control(rule):
    assert controls_for_rule(rule.rule_id), f"{rule.rule_id} is not referenced by any compliance control"


@by_id
def test_metadata_serialises(rule):
    data = rule.metadata.as_dict()
    assert data["rule_id"] == rule.rule_id
    assert data["severity"] == rule.metadata.severity.value
    assert isinstance(data["references"], list)


def test_catalog_only_references_registered_rules():
    referenced = {rid for fw in FRAMEWORKS for rid in fw.rule_ids()}
    assert referenced <= set(RULE_IDS), sorted(referenced - set(RULE_IDS))


def test_for_type_and_contains():
    s3_rules = REGISTRY.for_type(rt.S3_BUCKET)
    assert s3_rules and all(r.resource_type == rt.S3_BUCKET for r in s3_rules)
    assert "S3-001" in REGISTRY
    assert "NOPE-999" not in REGISTRY
    assert REGISTRY.get("NOPE-999") is None
    assert REGISTRY.get("S3-001").rule_id == "S3-001"


def test_without_excludes_rules_and_leaves_original_untouched():
    reduced = REGISTRY.without(["S3-001", "IAM-001", "UNKNOWN-001"])
    assert len(reduced) == len(REGISTRY) - 2
    assert "S3-001" not in reduced and reduced.get("S3-001") is None
    assert "IAM-001" not in reduced
    assert all(r not in reduced.for_type(rt.S3_BUCKET) for r in REGISTRY.for_type(rt.S3_BUCKET)
               if r.rule_id == "S3-001")
    assert "S3-001" in REGISTRY and len(REGISTRY) == len(RULES)


def test_without_nothing_is_equivalent():
    assert [r.rule_id for r in REGISTRY.without([]).all()] == RULE_IDS


def test_registry_add_rejects_duplicate_ids():
    rule = REGISTRY.get("S3-001")
    with pytest.raises(ValueError, match="Duplicate rule id S3-001"):
        RuleRegistry([rule, rule])


def test_register_decorator_rejects_duplicate_ids():
    existing = type(REGISTRY.get("IAM-001"))

    with pytest.raises(ValueError, match="Duplicate rule id IAM-001"):
        @register
        class Clone(existing):  # noqa: F811 - same metadata, different class
            pass


def test_register_decorator_requires_metadata():
    class NoMetadata:  # deliberately not a Rule
        pass

    with pytest.raises(TypeError):
        register(NoMetadata)


def test_every_rule_has_unit_tests():
    """Guard: a newly added rule must come with tests in this directory."""
    here = Path(__file__).parent
    text = "\n".join(p.read_text() for p in here.glob("test_*_rules.py"))
    missing = [rid for rid in RULE_IDS if f'"{rid}"' not in text]
    assert not missing, f"rules without unit tests: {missing}"
