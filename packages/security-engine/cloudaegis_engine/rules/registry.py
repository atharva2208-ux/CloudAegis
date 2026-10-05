"""Rule registry.

Rules self-register via the :func:`register` decorator when their module is
imported. :func:`default_registry` imports every built-in rule pack once.
"""

from __future__ import annotations

import importlib
from collections import defaultdict
from typing import Iterable, TypeVar

from cloudaegis_engine.rules.base import Rule

R = TypeVar("R", bound=type[Rule])

_BUILTIN_PACKS = (
    "cloudaegis_engine.rules.aws.iam",
    "cloudaegis_engine.rules.aws.s3",
    "cloudaegis_engine.rules.aws.ec2",
    "cloudaegis_engine.rules.aws.rds",
    "cloudaegis_engine.rules.aws.cloudtrail",
    "cloudaegis_engine.rules.aws.vpc",
    "cloudaegis_engine.rules.aws.lambda_",
    "cloudaegis_engine.rules.aws.kms",
    "cloudaegis_engine.rules.aws.secretsmanager",
    "cloudaegis_engine.rules.aws.ecr",
)

_registered: list[type[Rule]] = []


def register(rule_cls: R) -> R:
    """Class decorator that adds a rule to the global built-in set."""
    if not hasattr(rule_cls, "metadata"):
        raise TypeError(f"{rule_cls.__name__} has no metadata")
    if any(r.metadata.rule_id == rule_cls.metadata.rule_id for r in _registered):
        raise ValueError(f"Duplicate rule id {rule_cls.metadata.rule_id}")
    _registered.append(rule_cls)
    return rule_cls


class RuleRegistry:
    def __init__(self, rules: Iterable[Rule] = ()) -> None:
        self._rules: dict[str, Rule] = {}
        self._by_type: dict[str, list[Rule]] = defaultdict(list)
        for rule in rules:
            self.add(rule)

    def add(self, rule: Rule) -> None:
        if rule.rule_id in self._rules:
            raise ValueError(f"Duplicate rule id {rule.rule_id}")
        self._rules[rule.rule_id] = rule
        self._by_type[rule.resource_type].append(rule)

    def get(self, rule_id: str) -> Rule | None:
        return self._rules.get(rule_id)

    def all(self) -> list[Rule]:
        return sorted(self._rules.values(), key=lambda r: r.rule_id)

    def for_type(self, resource_type: str) -> list[Rule]:
        return list(self._by_type.get(resource_type, ()))

    def services(self) -> list[str]:
        return sorted({r.metadata.service for r in self._rules.values()})

    def without(self, disabled: Iterable[str]) -> "RuleRegistry":
        disabled_set = set(disabled)
        return RuleRegistry(r for r in self.all() if r.rule_id not in disabled_set)

    def __len__(self) -> int:
        return len(self._rules)

    def __contains__(self, rule_id: object) -> bool:
        return rule_id in self._rules


_default: RuleRegistry | None = None


def default_registry() -> RuleRegistry:
    global _default
    if _default is None:
        for module in _BUILTIN_PACKS:
            importlib.import_module(module)
        _default = RuleRegistry(cls() for cls in _registered)
    return _default
