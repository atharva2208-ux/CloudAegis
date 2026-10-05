"""Security score and asset risk calculation.

Security score (0–100)
----------------------
Every (rule, resource) evaluation is a *check*. Each check carries the
weight of its rule's severity::

    CRITICAL 10   HIGH 5   MEDIUM 2   LOW 1   INFO 0

``weighted pass rate = 1 - (weight of failing checks / weight of all checks)``

Because a large estate full of passing checks can dilute a handful of
critical problems, an explicit penalty is applied for each open CRITICAL
finding (3 points each, capped at 25)::

    score = clamp(round(100 * weighted_pass_rate - critical_penalty), 0, 100)

Suppressed findings are excluded from the failing weight (they represent
accepted risk) but the check still counts toward the total.

Asset risk (0–100)
------------------
Sum of severity weights of an asset's open findings, multiplied by 1.5 if
the asset is publicly exposed, scaled ×4 and capped at 100.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Iterable, Mapping

from cloudaegis_engine.models import Severity

SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 5.0,
    Severity.MEDIUM: 2.0,
    Severity.LOW: 1.0,
    Severity.INFO: 0.0,
}

CRITICAL_PENALTY_PER_FINDING = 3
CRITICAL_PENALTY_CAP = 25
EXPOSURE_MULTIPLIER = 1.5


@dataclass(frozen=True)
class ScoreBreakdown:
    score: int
    total_checks: int
    failed_checks: int
    total_weight: float
    failed_weight: float
    weighted_pass_rate: float
    critical_findings: int
    critical_penalty: int
    weights: dict[str, float]
    formula: str

    def as_dict(self) -> dict:
        return asdict(self)


def calculate_security_score(
    checks: Iterable[tuple[Severity, bool]],
) -> ScoreBreakdown:
    """``checks`` yields ``(severity, failing)`` for each evaluation.

    ``failing`` must already exclude suppressed findings.
    """
    total_weight = failed_weight = 0.0
    total = failed = critical = 0
    for severity, failing in checks:
        weight = SEVERITY_WEIGHTS[severity]
        total += 1
        total_weight += weight
        if failing:
            failed += 1
            failed_weight += weight
            if severity is Severity.CRITICAL:
                critical += 1
    pass_rate = 1.0 - (failed_weight / total_weight) if total_weight else 1.0
    penalty = min(CRITICAL_PENALTY_CAP, critical * CRITICAL_PENALTY_PER_FINDING)
    score = max(0, min(100, round(100 * pass_rate - penalty)))
    return ScoreBreakdown(
        score=score,
        total_checks=total,
        failed_checks=failed,
        total_weight=round(total_weight, 2),
        failed_weight=round(failed_weight, 2),
        weighted_pass_rate=round(pass_rate, 4),
        critical_findings=critical,
        critical_penalty=penalty,
        weights={s.value: w for s, w in SEVERITY_WEIGHTS.items()},
        formula="score = 100 × (1 − failed_weight / total_weight) − min(25, 3 × open_critical)",
    )


def asset_risk_score(open_finding_severities: Iterable[Severity], public: bool) -> int:
    raw = sum(SEVERITY_WEIGHTS[s] for s in open_finding_severities)
    if public:
        raw *= EXPOSURE_MULTIPLIER
    return int(min(100, round(raw * 4)))


def risk_level(score: int) -> str:
    if score >= 70:
        return "CRITICAL"
    if score >= 40:
        return "HIGH"
    if score >= 15:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def severity_counts(severities: Iterable[Severity]) -> Mapping[str, int]:
    counts = {s.value: 0 for s in Severity}
    for s in severities:
        counts[s.value] += 1
    return counts
