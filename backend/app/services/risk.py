"""Deterministic, explainable vulnerability and asset prioritisation.

Owner: assets team (see ``docs/backend-conventions.md`` §9). The score is a
bounded, additive model (0..100) that deliberately combines *several* signals so
that a raw CVSS number can never dominate remediation order:

======================  ======  ==============================================
Factor                  Max     Rationale
======================  ======  ==============================================
CVSS base               30      Technical severity, normalised from 0-10.
EPSS probability        20      Probability of exploitation in the wild.
CISA KEV                15      Confirmed in-the-wild exploitation.
Exploitability flag     5       Product/exploit evidence from the scanner.
Asset criticality       15      Business impact (1..5).
Environment             6       Production before staging before dev/test.
Exposure                12      Internet-facing before DMZ before internal.
Threat-intel match      10      Active indicators matching the asset IP/domain.
======================  ======  ==============================================

The function is pure and deterministic: identical inputs always produce the
same score and breakdown, which makes ordering assertions stable in tests and
audit explanations reproducible.
"""

from __future__ import annotations

import math
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.models.ti import ThreatIndicator

MAX_SCORE = 100.0

CVSS_WEIGHT = 30.0
EPSS_WEIGHT = 20.0
KEV_POINTS = 15.0
EXPLOITABLE_POINTS = 5.0
CRITICALITY_WEIGHT = 15.0
THREAT_MATCH_POINTS = 10.0

ENVIRONMENT_POINTS: dict[str, float] = {
    "production": 6.0,
    "staging": 3.0,
    "development": 1.0,
    "test": 0.0,
}

EXPOSURE_POINTS: dict[str, float] = {
    "public": 12.0,
    "internet": 12.0,
    "dmz": 8.0,
    "internal": 0.0,
}

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

# Indicator types that can be matched against an asset's addresses/names.
_ASSET_INDICATOR_TYPES = ("ip", "domain")


@dataclass(frozen=True)
class RiskFactor:
    """One explainable component of the priority score."""

    name: str
    points: float
    detail: str


@dataclass(frozen=True)
class RiskScore:
    """Result of a deterministic prioritisation pass."""

    score: float
    factors: tuple[RiskFactor, ...]
    reason: str


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def _as_float(value: Any, default: float = 0.0) -> float:
    if value is None or isinstance(value, bool):
        return default
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    if math.isnan(number) or math.isinf(number):
        return default
    return number


def severity_from_cvss(cvss_score: float | None) -> str:
    """Map a CVSS v3 base score to the platform severity vocabulary."""
    score = _clamp(_as_float(cvss_score), 0.0, 10.0)
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def compute_priority(
    *,
    cvss_score: float | None,
    epss_score: float | None = None,
    kev: bool = False,
    exploitable: bool = False,
    asset_criticality: int | None = 3,
    environment: str | None = "production",
    exposure: str | None = "internal",
    threat_match: bool = False,
) -> RiskScore:
    """Compute the 0..100 priority score plus a human-readable breakdown.

    Every input is clamped to its documented domain so corrupted scanner data
    cannot produce an out-of-range score or a negative factor.
    """
    factors: list[RiskFactor] = []

    cvss = _clamp(_as_float(cvss_score), 0.0, 10.0)
    cvss_points = round(cvss / 10.0 * CVSS_WEIGHT, 2)
    factors.append(RiskFactor("cvss", cvss_points, f"CVSS {cvss:.1f}/10"))

    epss = _clamp(_as_float(epss_score), 0.0, 1.0)
    epss_points = round(epss * EPSS_WEIGHT, 2)
    factors.append(RiskFactor("epss", epss_points, f"EPSS {epss:.3f}"))

    kev_points = KEV_POINTS if kev else 0.0
    factors.append(RiskFactor("kev", kev_points, "CISA KEV" if kev else "not in KEV"))

    exploit_points = EXPLOITABLE_POINTS if exploitable else 0.0
    factors.append(
        RiskFactor("exploitable", exploit_points, "exploit evidence" if exploitable else "no exploit evidence")
    )

    criticality = int(_clamp(_as_float(asset_criticality, 3.0), 1.0, 5.0))
    criticality_points = round((criticality - 1) / 4.0 * CRITICALITY_WEIGHT, 2)
    factors.append(RiskFactor("asset_criticality", criticality_points, f"criticality {criticality}/5"))

    env_key = (environment or "production").strip().lower()
    env_points = ENVIRONMENT_POINTS.get(env_key, 0.0)
    factors.append(RiskFactor("environment", env_points, f"environment {env_key}"))

    exposure_key = (exposure or "internal").strip().lower()
    exposure_points = EXPOSURE_POINTS.get(exposure_key, 0.0)
    factors.append(RiskFactor("exposure", exposure_points, f"exposure {exposure_key}"))

    threat_points = THREAT_MATCH_POINTS if threat_match else 0.0
    factors.append(
        RiskFactor("threat_intel", threat_points, "active indicator match" if threat_match else "no indicator match")
    )

    raw = sum(factor.points for factor in factors)
    score = round(_clamp(raw, 0.0, MAX_SCORE), 2)
    reason = f"priority={score:.2f} | " + " | ".join(
        f"{factor.name}={factor.points:.2f} ({factor.detail})" for factor in factors
    )
    return RiskScore(score=score, factors=tuple(factors), reason=reason)


def asset_criticality(asset: Any) -> int:
    """Return the clamped criticality of an asset-like object (default 3)."""
    value = getattr(asset, "criticality", 3)
    return int(_clamp(_as_float(value, 3.0), 1.0, 5.0))


def apply_priority(
    vulnerability: Any,
    asset: Any | None = None,
    *,
    threat_match: bool = False,
) -> RiskScore:
    """Recalculate and persist priority fields on a vulnerability row.

    The caller owns the transaction. ``priority_reason`` always contains the
    full factor breakdown so analysts can justify remediation order.
    """
    result = compute_priority(
        cvss_score=getattr(vulnerability, "cvss_score", None),
        epss_score=getattr(vulnerability, "epss_score", None),
        kev=bool(getattr(vulnerability, "kev", False)),
        exploitable=bool(getattr(vulnerability, "exploitable", False)),
        asset_criticality=asset_criticality(asset),
        environment=getattr(asset, "environment", "production") if asset is not None else "production",
        exposure=getattr(vulnerability, "exposure", "internal"),
        threat_match=threat_match,
    )
    vulnerability.priority_score = result.score
    vulnerability.priority_reason = result.reason
    return result


def normalize_indicator_value(value: str) -> str:
    return value.strip().lower().rstrip(".")


def threat_indicator_values(db: Session, org_id: Any, values: Iterable[str]) -> set[str]:
    """Return the subset of ``values`` present as active threat indicators.

    Indicators are matched case-insensitively. Global indicators (org_id NULL)
    are included because they are curated intelligence shared with every tenant;
    indicators from other organizations are never visible.
    """
    candidates = {normalize_indicator_value(value) for value in values if value}
    if not candidates:
        return set()
    rows = db.execute(
        select(ThreatIndicator.value).where(
            or_(ThreatIndicator.org_id == org_id, ThreatIndicator.org_id.is_(None)),
            ThreatIndicator.active.is_(True),
            ThreatIndicator.indicator_type.in_(_ASSET_INDICATOR_TYPES),
            func.lower(ThreatIndicator.value).in_(candidates),
        )
    ).scalars()
    return {normalize_indicator_value(row) for row in rows}


def asset_matches_threat_intel(db: Session, org_id: Any, asset: Any | None) -> bool:
    """True when any active indicator matches the asset IPs or hostnames."""
    if asset is None:
        return False
    values: list[str] = []
    for field in ("ip_addresses", "hostnames"):
        items = getattr(asset, field, None) or []
        if isinstance(items, list):
            values.extend(str(item) for item in items)
    return bool(threat_indicator_values(db, org_id, values))


__all__ = [
    "ENVIRONMENT_POINTS",
    "EXPOSURE_POINTS",
    "MAX_SCORE",
    "RiskFactor",
    "RiskScore",
    "SEVERITY_ORDER",
    "apply_priority",
    "asset_criticality",
    "asset_matches_threat_intel",
    "compute_priority",
    "normalize_indicator_value",
    "severity_from_cvss",
    "threat_indicator_values",
]
