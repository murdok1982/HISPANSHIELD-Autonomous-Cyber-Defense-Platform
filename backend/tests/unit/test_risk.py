"""Unit tests for the deterministic risk/priority engine."""

from __future__ import annotations

from types import SimpleNamespace

from app.services import risk


def test_kev_public_beats_higher_raw_cvss() -> None:
    raw_cvss = risk.compute_priority(
        cvss_score=9.8,
        epss_score=0.02,
        kev=False,
        exploitable=False,
        asset_criticality=2,
        environment="production",
        exposure="internal",
        threat_match=False,
    )
    exploited = risk.compute_priority(
        cvss_score=7.5,
        epss_score=0.9,
        kev=True,
        exploitable=True,
        asset_criticality=5,
        environment="production",
        exposure="public",
        threat_match=True,
    )
    assert exploited.score > raw_cvss.score
    assert exploited.score <= risk.MAX_SCORE


def test_criticality_and_exposure_ordering() -> None:
    base = {
        "cvss_score": 8.0,
        "epss_score": 0.4,
        "kev": False,
        "exploitable": False,
        "environment": "production",
        "threat_match": False,
    }
    critical_public = risk.compute_priority(**base, asset_criticality=5, exposure="public")
    medium_dmz = risk.compute_priority(**base, asset_criticality=3, exposure="dmz")
    low_internal = risk.compute_priority(**base, asset_criticality=1, exposure="internal")
    assert critical_public.score > medium_dmz.score > low_internal.score
    assert critical_public.factors[4].name == "asset_criticality"
    assert critical_public.factors[6].name == "exposure"


def test_threat_match_adds_exactly_ten_points() -> None:
    base = {
        "cvss_score": 6.0,
        "epss_score": 0.2,
        "kev": False,
        "exploitable": False,
        "asset_criticality": 3,
        "exposure": "internal",
    }
    without = risk.compute_priority(**base, environment="production", threat_match=False)
    with_match = risk.compute_priority(**base, environment="production", threat_match=True)
    assert round(with_match.score - without.score, 2) == 10.0
    assert "active indicator match" in with_match.reason


def test_environment_points_order() -> None:
    production = risk.compute_priority(cvss_score=5.0, environment="production", exposure="internal")
    staging = risk.compute_priority(cvss_score=5.0, environment="staging", exposure="internal")
    development = risk.compute_priority(cvss_score=5.0, environment="development", exposure="internal")
    test = risk.compute_priority(cvss_score=5.0, environment="test", exposure="internal")
    assert production.score > staging.score > development.score > test.score


def test_bounds_clamping_and_determinism() -> None:
    extreme = risk.compute_priority(
        cvss_score=99.0,
        epss_score=5.0,
        kev=True,
        exploitable=True,
        asset_criticality=99,
        environment="production",
        exposure="public",
        threat_match=True,
    )
    assert extreme.score == 100.0

    negative = risk.compute_priority(
        cvss_score=-5.0,
        epss_score=-1.0,
        asset_criticality=-10,
        environment="unknown",
        exposure="unknown",
    )
    assert negative.score == 0.0

    first = risk.compute_priority(cvss_score=7.7, epss_score=0.33, kev=True, asset_criticality=4, threat_match=True)
    second = risk.compute_priority(cvss_score=7.7, epss_score=0.33, kev=True, asset_criticality=4, threat_match=True)
    assert first == second
    assert "priority=" in first.reason
    assert "threat_intel=10.00" in first.reason


def test_severity_mapping() -> None:
    assert risk.severity_from_cvss(9.8) == "critical"
    assert risk.severity_from_cvss(7.0) == "high"
    assert risk.severity_from_cvss(4.0) == "medium"
    assert risk.severity_from_cvss(1.2) == "low"
    assert risk.severity_from_cvss(0) == "info"
    assert risk.severity_from_cvss(None) == "info"


def test_apply_priority_persists_fields_and_uses_asset_context() -> None:
    vulnerability = SimpleNamespace(
        cvss_score=8.1,
        epss_score=0.4,
        kev=False,
        exploitable=True,
        exposure="public",
        priority_score=0.0,
        priority_reason=None,
    )
    asset = SimpleNamespace(criticality=5, environment="production", ip_addresses=[], hostnames=[])
    result = risk.apply_priority(vulnerability, asset, threat_match=True)
    assert vulnerability.priority_score == result.score
    assert vulnerability.priority_reason == result.reason
    assert "asset_criticality=15.00" in result.reason
    assert "exposure=12.00" in result.reason

    without_asset = SimpleNamespace(
        cvss_score=8.1,
        epss_score=0.4,
        kev=False,
        exploitable=True,
        exposure="public",
        priority_score=0.0,
        priority_reason=None,
    )
    defaulted = risk.apply_priority(without_asset)
    assert defaulted.score < result.score
    assert "criticality 3/5" in defaulted.reason


def test_scores_are_reproducible_for_ordering() -> None:
    scores = [
        risk.compute_priority(cvss_score=cvss, asset_criticality=criticality).score
        for cvss, criticality in ((9.8, 1), (9.8, 5), (5.0, 5), (7.0, 4))
    ]
    assert sorted(scores) == [35.4, 36.0, 38.25, 50.4]
    assert len(set(scores)) == len(scores)
