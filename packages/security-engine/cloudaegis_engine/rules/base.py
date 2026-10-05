"""Base class for detection rules.

A rule declares its metadata and implements :meth:`Rule.evaluate`, which
receives one normalized resource plus a :class:`RuleContext` and returns a
:class:`RuleResult` (PASS/FAIL with evidence) or ``None`` when the rule
does not apply to that particular resource (for example a rotation rule on
an asymmetric KMS key).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, ClassVar

from cloudaegis_engine.models import CheckOutcome, Inventory, Resource, RuleMetadata, RuleResult


@dataclass
class RuleContext:
    inventory: Inventory
    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    # Thresholds are configurable so organisations can tune them.
    stale_credential_days: int = 90
    unused_user_days: int = 90
    secret_rotation_days: int = 90


class Rule(ABC):
    metadata: ClassVar[RuleMetadata]

    @property
    def rule_id(self) -> str:
        return self.metadata.rule_id

    @property
    def resource_type(self) -> str:
        return self.metadata.resource_type

    @abstractmethod
    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        """Evaluate this rule against ``resource``."""

    # Convenience constructors -------------------------------------------------
    def passed(self, resource: Resource, evidence: dict[str, Any] | None = None) -> RuleResult:
        return RuleResult(
            rule_id=self.rule_id,
            resource_uid=resource.uid,
            outcome=CheckOutcome.PASS,
            evidence=evidence or {},
        )

    def failed(
        self, resource: Resource, evidence: dict[str, Any], message: str = ""
    ) -> RuleResult:
        return RuleResult(
            rule_id=self.rule_id,
            resource_uid=resource.uid,
            outcome=CheckOutcome.FAIL,
            evidence=evidence,
            message=message or self.metadata.title,
        )

    def check(
        self,
        resource: Resource,
        condition_failed: bool,
        evidence: dict[str, Any],
        message: str = "",
    ) -> RuleResult:
        if condition_failed:
            return self.failed(resource, evidence, message)
        return self.passed(resource, evidence)
