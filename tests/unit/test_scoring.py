"""Security score and asset risk arithmetic."""

from __future__ import annotations

import pytest

from cloudaegis_engine.models import Severity
from cloudaegis_engine.scoring import asset_risk_score, calculate_security_score
from cloudaegis_engine.scoring.posture import (
    CRITICAL_PENALTY_CAP,
    SEVERITY_WEIGHTS,
    risk_level,
    severity_counts,
)

C, H, M, L, I = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO


def test_no_checks_scores_100():
    result = calculate_security_score([])
    assert result.score == 100
    assert result.total_checks == 0
    assert result.weighted_pass_rate == 1.0


def test_all_passing_scores_100():
    result = calculate_security_score([(C, False), (H, False), (L, False)])
    assert result.score == 100
    assert result.failed_checks == 0
    assert result.critical_penalty == 0


def test_weighted_pass_rate_uses_severity_weights():
    # total weight = 10 + 5 + 2 + 1 = 18; failing = 5 (one HIGH) -> pass rate 13/18
    result = calculate_security_score([(C, False), (H, True), (M, False), (L, False)])
    assert result.total_weight == 18
    assert result.failed_weight == 5
    assert result.weighted_pass_rate == pytest.approx(13 / 18, abs=1e-4)
    assert result.score == round(100 * 13 / 18)


def test_critical_penalty_is_three_points_each():
    checks = [(C, True)] + [(L, False)] * 990  # failing weight 10 of 1000
    result = calculate_security_score(checks)
    assert result.critical_findings == 1
    assert result.critical_penalty == 3
    assert result.score == round(100 * 0.99 - 3)


def test_critical_penalty_is_capped():
    checks = [(C, True)] * 20 + [(L, False)] * 100_000
    result = calculate_security_score(checks)
    assert result.critical_penalty == CRITICAL_PENALTY_CAP


def test_info_findings_do_not_reduce_score():
    result = calculate_security_score([(I, True), (I, True), (L, False)])
    assert result.score == 100
    assert result.failed_checks == 2


def test_score_never_negative():
    result = calculate_security_score([(C, True)] * 50)
    assert result.score == 0


def test_breakdown_is_explainable():
    data = calculate_security_score([(H, True), (L, False)]).as_dict()
    for key in ("score", "formula", "weights", "weighted_pass_rate", "critical_penalty", "total_checks"):
        assert key in data
    assert data["weights"] == {s.value: w for s, w in SEVERITY_WEIGHTS.items()}


def test_more_failures_never_increase_score():
    base = [(M, False)] * 20 + [(H, False)] * 10
    previous = 101
    for failing in range(0, 30):
        checks = [(sev, i < failing) for i, (sev, _) in enumerate(base)]
        score = calculate_security_score(checks).score
        assert score <= previous
        previous = score


@pytest.mark.parametrize(
    "severities,public,expected",
    [
        ([], False, 0),
        ([L], False, 4),
        ([M, L], False, 12),
        ([H], True, 30),
        ([C, C, C], False, 100),
    ],
)
def test_asset_risk_score(severities, public, expected):
    assert asset_risk_score(severities, public) == expected


def test_public_exposure_increases_asset_risk():
    assert asset_risk_score([H], True) > asset_risk_score([H], False)


@pytest.mark.parametrize("score,level", [(0, "NONE"), (1, "LOW"), (15, "MEDIUM"), (40, "HIGH"), (70, "CRITICAL"), (100, "CRITICAL")])
def test_risk_levels(score, level):
    assert risk_level(score) == level


def test_severity_counts_includes_every_level():
    counts = severity_counts([C, C, L])
    assert counts == {"CRITICAL": 2, "HIGH": 0, "MEDIUM": 0, "LOW": 1, "INFO": 0}
