"""Core data structures shared by providers, rules, scoring and compliance."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Iterator


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @classmethod
    def ordered(cls) -> list["Severity"]:
        return sorted(cls, key=lambda s: s.rank)


_SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class CheckOutcome(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"


@dataclass(frozen=True)
class Relationship:
    """A directed edge between two resources (e.g. instance -> security group)."""

    kind: str
    target_uid: str


@dataclass
class Resource:
    """A cloud resource normalized into a provider-neutral shape.

    ``uid`` is globally unique within a provider (an ARN for AWS).
    ``properties`` holds the configuration attributes the detection rules
    evaluate. Providers are responsible for producing the documented
    property names for every resource type (see docs/detection-rules.md).
    """

    uid: str
    resource_type: str
    service: str
    name: str
    region: str
    account_id: str
    properties: dict[str, Any] = field(default_factory=dict)
    tags: dict[str, str] = field(default_factory=dict)
    relationships: list[Relationship] = field(default_factory=list)

    def prop(self, key: str, default: Any = None) -> Any:
        return self.properties.get(key, default)


class Inventory:
    """Indexed collection of discovered resources.

    Rules receive the inventory so they can make cross-resource decisions,
    e.g. "is the bucket this trail writes to public?".
    """

    def __init__(self, resources: Iterable[Resource] = ()) -> None:
        self._by_uid: dict[str, Resource] = {}
        self._by_type: dict[str, list[Resource]] = defaultdict(list)
        for resource in resources:
            self.add(resource)

    def add(self, resource: Resource) -> None:
        if resource.uid in self._by_uid:
            return
        self._by_uid[resource.uid] = resource
        self._by_type[resource.resource_type].append(resource)

    def get(self, uid: str | None) -> Resource | None:
        if uid is None:
            return None
        return self._by_uid.get(uid)

    def of_type(self, resource_type: str) -> list[Resource]:
        return list(self._by_type.get(resource_type, ()))

    def find(self, resource_type: str, **props: Any) -> Iterator[Resource]:
        for resource in self._by_type.get(resource_type, ()):
            if all(resource.properties.get(k) == v for k, v in props.items()):
                yield resource

    def __iter__(self) -> Iterator[Resource]:
        return iter(self._by_uid.values())

    def __len__(self) -> int:
        return len(self._by_uid)

    @property
    def resource_types(self) -> list[str]:
        return sorted(self._by_type)


@dataclass(frozen=True)
class RuleMetadata:
    rule_id: str
    title: str
    severity: Severity
    service: str
    category: str
    resource_type: str
    description: str
    impact: str
    remediation: str
    remediation_steps: tuple[str, ...] = ()
    remediation_cli: str | None = None
    references: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "service": self.service,
            "category": self.category,
            "resource_type": self.resource_type,
            "description": self.description,
            "impact": self.impact,
            "remediation": self.remediation,
            "remediation_steps": list(self.remediation_steps),
            "remediation_cli": self.remediation_cli,
            "references": list(self.references),
        }


@dataclass
class RuleResult:
    """The outcome of evaluating one rule against one resource."""

    rule_id: str
    resource_uid: str
    outcome: CheckOutcome
    evidence: dict[str, Any] = field(default_factory=dict)
    message: str = ""

    @property
    def failed(self) -> bool:
        return self.outcome is CheckOutcome.FAIL
