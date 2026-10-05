"""Evaluate compliance controls from per-rule check statistics.

A control is:

* ``FAIL``           — at least one mapped rule has a failing (open) result;
* ``PASS``           — every mapped rule evaluated at least one resource and none failed;
* ``NOT_APPLICABLE`` — no mapped rule evaluated any resource (nothing in scope).

Each assessed control also has a *compliance ratio*: the share of its
resource checks that passed. The framework score is the mean compliance
ratio of all assessed controls, so one non-compliant bucket out of 180
lowers the score proportionally instead of zeroing the control. The strict
pass/fail control count is reported alongside it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

from cloudaegis_engine.compliance.catalog import FRAMEWORKS, Framework


@dataclass(frozen=True)
class RuleStats:
    evaluated: int = 0
    failed: int = 0


@dataclass
class ControlResult:
    control_id: str
    title: str
    section: str
    status: str
    rule_ids: list[str]
    failing_rules: list[str] = field(default_factory=list)
    failed_resources: int = 0
    evaluated_resources: int = 0

    @property
    def compliance_ratio(self) -> float | None:
        if self.evaluated_resources == 0:
            return None
        return 1.0 - self.failed_resources / self.evaluated_resources


@dataclass
class FrameworkResult:
    key: str
    name: str
    short_name: str
    version: str
    passed: int
    failed: int
    not_applicable: int
    controls: list[ControlResult]

    @property
    def score(self) -> float:
        ratios = [c.compliance_ratio for c in self.controls if c.compliance_ratio is not None]
        return round(100.0 * sum(ratios) / len(ratios), 1) if ratios else 100.0

    def as_dict(self) -> dict:
        return {
            "key": self.key,
            "name": self.name,
            "short_name": self.short_name,
            "version": self.version,
            "score": self.score,
            "passed": self.passed,
            "failed": self.failed,
            "not_applicable": self.not_applicable,
            "total": len(self.controls),
        }


def evaluate_framework(framework: Framework, stats: Mapping[str, RuleStats]) -> FrameworkResult:
    results: list[ControlResult] = []
    passed = failed = na = 0
    for control in framework.controls:
        rule_stats = [stats.get(r, RuleStats()) for r in control.rule_ids]
        failing = [r for r, s in zip(control.rule_ids, rule_stats) if s.failed > 0]
        evaluated = sum(s.evaluated for s in rule_stats)
        if failing:
            status = "FAIL"
            failed += 1
        elif evaluated == 0:
            status = "NOT_APPLICABLE"
            na += 1
        else:
            status = "PASS"
            passed += 1
        results.append(
            ControlResult(
                control_id=control.control_id,
                title=control.title,
                section=control.section,
                status=status,
                rule_ids=list(control.rule_ids),
                failing_rules=failing,
                failed_resources=sum(s.failed for s in rule_stats),
                evaluated_resources=evaluated,
            )
        )
    return FrameworkResult(
        key=framework.key,
        name=framework.name,
        short_name=framework.short_name,
        version=framework.version,
        passed=passed,
        failed=failed,
        not_applicable=na,
        controls=results,
    )


def evaluate_all(stats: Mapping[str, RuleStats]) -> list[FrameworkResult]:
    return [evaluate_framework(f, stats) for f in FRAMEWORKS]
