"""OT passive monitoring: baseline learning, anomaly alerts and IEC 62443 posture.

Safety invariant: there is no code path in this module (or its router) that
opens a connection to a PLC/RTU or writes a value. Telemetry arrives out-of-band
from passive taps and is only ever used to learn a baseline and raise alerts.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.crypto import sha256_hex
from app.core.db import utcnow
from app.core.errors import NotFound, ValidationFailure
from app.models.assets import Asset, OTDevice, Vulnerability, Zone
from app.models.events import Alert
from app.modules.assets.schemas import AssetRef
from app.modules.ot.protocols import OT_PROTOCOLS, ot_protocol_spec
from app.modules.ot.schemas import OTDeviceOut, OTPostureOut, OTZonePostureOut

MIN_BASELINE_SAMPLES = 5
BASELINE_STD_MULTIPLIER = 3.0
MAX_ALLOWED_VALUES = 32
STALE_AFTER = timedelta(hours=24)

_SEVERITY_RISK = {"critical": 90.0, "high": 75.0, "medium": 55.0, "low": 30.0, "info": 10.0}


@dataclass
class DetectionOutcome:
    anomaly: bool
    alert_created: bool = False
    alert_deduplicated: bool = False
    baseline_updated: bool = False
    reason: str | None = None
    severity: str | None = None


def get_ot_device(db: Session, org_id: UUID, asset_id: UUID) -> tuple[Asset, OTDevice]:
    asset = db.get(Asset, asset_id)
    if asset is None or asset.org_id != org_id or asset.kind != "ot":
        raise NotFound("OT device")
    device = db.execute(
        select(OTDevice).where(OTDevice.asset_id == asset.id, OTDevice.org_id == org_id)
    ).scalar_one_or_none()
    if device is None:
        raise NotFound("OT device")
    return asset, device


def locate_ot_asset(
    db: Session, org_id: UUID, *, asset_id: UUID | None, asset_key: str | None
) -> tuple[Asset, OTDevice]:
    asset: Asset | None = None
    if asset_id is not None:
        asset = db.get(Asset, asset_id)
    elif asset_key:
        asset = db.execute(
            select(Asset).where(Asset.org_id == org_id, Asset.asset_key == asset_key)
        ).scalar_one_or_none()
    if asset is None or asset.org_id != org_id:
        raise NotFound("OT device")
    if asset.kind != "ot":
        raise ValidationFailure([{"field": "asset_id", "message": "Asset is not of kind ot"}])
    device = db.execute(
        select(OTDevice).where(OTDevice.asset_id == asset.id, OTDevice.org_id == org_id)
    ).scalar_one_or_none()
    if device is None:
        raise NotFound("OT device profile")
    return asset, device


def effective_zone_id(device: OTDevice, asset: Asset) -> UUID | None:
    return device.zone_id or asset.zone_id


def risk_flags(device: OTDevice, asset: Asset, *, now: datetime | None = None) -> list[str]:
    now = now or utcnow()
    flags: set[str] = set()
    if not device.protocols:
        flags.add("no_protocol_declared")
    if effective_zone_id(device, asset) is None:
        flags.add("unzoned")
    if device.safety_critical:
        flags.add("safety_critical")
    if device.last_telemetry_at is None:
        flags.add("no_telemetry")
    else:
        last = device.last_telemetry_at
        if last.tzinfo is None:
            last = last.replace(tzinfo=UTC)
        if now - last > STALE_AFTER:
            flags.add("telemetry_stale")
    if not device.firmware_version and not asset.firmware:
        flags.add("unknown_firmware")
    if (device.baseline or {}).get("anomalies", 0) > 0:
        flags.add("baseline_anomalies")
    return sorted(flags)


def serialize_device(device: OTDevice, asset: Asset, zone: Zone | None = None) -> OTDeviceOut:
    return OTDeviceOut(
        asset_id=device.asset_id,
        asset=AssetRef.model_validate(asset),
        zone_id=effective_zone_id(device, asset),
        zone_name=zone.name if zone else None,
        protocols=list(device.protocols or []),
        safety_critical=device.safety_critical,
        passive_only=device.passive_only,
        controller_model=device.controller_model,
        firmware_version=device.firmware_version,
        last_telemetry_at=device.last_telemetry_at,
        baseline=dict(device.baseline or {}),
        risk_flags=risk_flags(device, asset),
    )


def protocol_catalogue() -> list[dict[str, Any]]:
    return [dict(entry) for entry in OT_PROTOCOLS]


def _dedupe_key(asset: Asset, metric: str, observed_at: datetime) -> str:
    hour = observed_at.astimezone(UTC).replace(minute=0, second=0, microsecond=0).isoformat()
    return sha256_hex(f"ot:{asset.id}:{metric}:{hour}")


def _raise_alert(
    db: Session,
    org_id: UUID,
    asset: Asset,
    *,
    metric: str,
    observed_at: datetime,
    severity: str,
    title: str,
    description: str,
    evidence: dict[str, Any],
) -> tuple[bool, bool]:
    """Create or dedupe an alert. Returns (created, deduplicated)."""
    key = _dedupe_key(asset, metric, observed_at)
    existing = db.execute(select(Alert).where(Alert.org_id == org_id, Alert.dedupe_key == key)).scalar_one_or_none()
    risk = _SEVERITY_RISK.get(severity, 50.0)
    if existing is not None:
        existing.count += 1
        existing.last_seen = observed_at
        existing.risk_score = max(existing.risk_score, risk)
        return False, True
    db.add(
        Alert(
            org_id=org_id,
            title=title[:300],
            description=description,
            severity=severity,
            status="new",
            dedupe_key=key,
            first_seen=observed_at,
            last_seen=observed_at,
            count=1,
            risk_score=risk,
            evidence=evidence,
            mitre=["T0836", "T0855"],
        )
    )
    db.flush()
    return True, False


def _severity_for(asset: Asset, device: OTDevice) -> str:
    if device.safety_critical or asset.criticality >= 4:
        return "high"
    return "medium"


def learn_and_detect(
    db: Session,
    org_id: UUID,
    asset: Asset,
    device: OTDevice,
    *,
    protocol: str,
    metric: str,
    value: float | str,
    observed_at: datetime,
) -> DetectionOutcome:
    """Update a Welford baseline and flag deviations beyond 3 sigma.

    Anomalous samples are *not* folded into the baseline: a hostile controller
    cannot slowly poison its own reference profile. Alerts are deduplicated per
    (asset, metric, hour) through the alert hash key.
    """
    baseline = dict(device.baseline or {})
    metrics: dict[str, Any] = dict(baseline.get("metrics") or {})
    known_protocols = list(device.protocols or [])
    outcome = DetectionOutcome(anomaly=False)

    if known_protocols and protocol not in known_protocols:
        severity = "high" if device.safety_critical else "medium"
        created, deduped = _raise_alert(
            db,
            org_id,
            asset,
            metric=f"protocol:{protocol}",
            observed_at=observed_at,
            severity=severity,
            title=f"Unauthorized OT protocol '{protocol}' observed on {asset.name}",
            description=(
                f"Asset {asset.asset_key} reported protocol '{protocol}' which is not in its approved "
                f"protocol set {known_protocols}. Passive observation only; no connection was made."
            ),
            evidence={
                "asset_id": str(asset.id),
                "asset_key": asset.asset_key,
                "protocol": protocol,
                "approved_protocols": known_protocols,
                "metric": metric,
                "observed_at": observed_at.isoformat(),
            },
        )
        outcome = DetectionOutcome(
            anomaly=True,
            alert_created=created,
            alert_deduplicated=deduped,
            reason="unauthorized_protocol",
            severity=severity,
        )
        baseline["anomalies"] = int(baseline.get("anomalies", 0)) + 1
        baseline["updated_at"] = utcnow().isoformat()
        device.baseline = baseline
        return outcome

    numeric = not isinstance(value, str)
    stats = dict(metrics.get(metric) or {})
    anomaly = False
    reason: str | None = None
    severity = _severity_for(asset, device)
    evidence: dict[str, Any] = {
        "asset_id": str(asset.id),
        "asset_key": asset.asset_key,
        "protocol": protocol,
        "metric": metric,
        "value": value,
        "observed_at": observed_at.isoformat(),
    }

    if numeric:
        sample = float(value)
        samples = int(stats.get("samples", 0))
        mean = float(stats.get("mean", 0.0))
        m2 = float(stats.get("m2", 0.0))
        std = math.sqrt(m2 / samples) if samples > 0 else 0.0
        if samples >= MIN_BASELINE_SAMPLES:
            threshold = BASELINE_STD_MULTIPLIER * std
            anomaly = (abs(sample - mean) > threshold) if std > 0 else (sample != mean)
            if anomaly:
                reason = "value_outside_baseline"
                evidence.update(
                    {
                        "baseline_mean": round(mean, 6),
                        "baseline_std": round(std, 6),
                        "samples": samples,
                        "z_score": round((sample - mean) / std, 6) if std > 0 else None,
                    }
                )
        if not anomaly:
            samples += 1
            delta = sample - mean
            mean += delta / samples
            m2 += delta * (sample - mean)
            stats.update(
                {
                    "samples": samples,
                    "mean": round(mean, 6),
                    "m2": round(m2, 6),
                    "std": round(math.sqrt(m2 / samples), 6) if samples > 0 else 0.0,
                    "min": round(min(float(stats.get("min", sample)), sample), 6),
                    "max": round(max(float(stats.get("max", sample)), sample), 6),
                    "last": sample,
                    "updated_at": utcnow().isoformat(),
                }
            )
            metrics[metric] = stats
            baseline["updated_at"] = utcnow().isoformat()
            baseline["metrics"] = metrics
            baseline["samples"] = int(baseline.get("samples", 0)) + 1
            device.baseline = baseline
            outcome.baseline_updated = True
    else:
        allowed = [str(item) for item in (stats.get("allowed") or [])]
        if len(allowed) >= MIN_BASELINE_SAMPLES - 2 and str(value) not in allowed:
            anomaly = True
            reason = "unexpected_categorical_value"
            evidence.update({"allowed_values": allowed, "samples": int(stats.get("samples", len(allowed)))})
        if not anomaly:
            if str(value) not in allowed and len(allowed) < MAX_ALLOWED_VALUES:
                allowed.append(str(value))
            stats.update(
                {
                    "samples": int(stats.get("samples", 0)) + 1,
                    "allowed": allowed,
                    "last": str(value),
                    "updated_at": utcnow().isoformat(),
                }
            )
            metrics[metric] = stats
            baseline["updated_at"] = utcnow().isoformat()
            baseline["metrics"] = metrics
            baseline["samples"] = int(baseline.get("samples", 0)) + 1
            device.baseline = baseline
            outcome.baseline_updated = True

    if anomaly:
        created, deduped = _raise_alert(
            db,
            org_id,
            asset,
            metric=metric,
            observed_at=observed_at,
            severity=severity,
            title=f"OT baseline anomaly on {asset.name}: {metric}",
            description=(
                f"Metric '{metric}' reported {value!r} on {asset.asset_key} ({protocol}), outside the learned "
                "passive baseline. HISPANSHIELD observed traffic only; verify with on-site staff."
            ),
            evidence={**evidence, "reason": reason},
        )
        baseline["anomalies"] = int(baseline.get("anomalies", 0)) + 1
        baseline["updated_at"] = utcnow().isoformat()
        device.baseline = baseline
        outcome.anomaly = True
        outcome.alert_created = created
        outcome.alert_deduplicated = deduped
        outcome.reason = reason
        outcome.severity = severity
    return outcome


def posture(db: Session, org_id: UUID) -> OTPostureOut:
    zones = list(db.execute(select(Zone).where(Zone.org_id == org_id)).scalars())
    rows = db.execute(
        select(OTDevice, Asset).join(Asset, Asset.id == OTDevice.asset_id).where(OTDevice.org_id == org_id)
    ).all()
    now = utcnow()
    zone_counts: dict[UUID, dict[str, int]] = {}
    zoned = 0
    safety_critical = 0
    monitored = 0
    unzoned = 0
    for device, asset in rows:
        zone_id = effective_zone_id(device, asset)
        if zone_id is None:
            unzoned += 1
        else:
            zoned += 1
            bucket = zone_counts.setdefault(zone_id, {"devices": 0, "safety_critical": 0})
            bucket["devices"] += 1
            if device.safety_critical:
                bucket["safety_critical"] += 1
        if device.safety_critical:
            safety_critical += 1
        if device.last_telemetry_at is not None:
            last = device.last_telemetry_at
            if last.tzinfo is None:
                last = last.replace(tzinfo=UTC)
            if now - last <= STALE_AFTER:
                monitored += 1

    total = len(rows)
    unmonitored = total - monitored
    zones_total = len(zones)
    conduits_total = sum(1 for zone in zones if zone.kind == "conduit")
    purdue_documented = sum(1 for zone in zones if zone.purdue_level is not None)
    zone_coverage = round(100.0 * zoned / total, 1) if total else 0.0
    conduit_coverage = round(100.0 * conduits_total / zones_total, 1) if zones_total else 0.0
    monitored_pct = round(100.0 * monitored / total, 1) if total else 0.0

    if total and zone_coverage >= 90.0 and unmonitored == 0 and purdue_documented == zones_total:
        posture_level = "aligned"
    elif total and zone_coverage >= 50.0:
        posture_level = "partial"
    else:
        posture_level = "initial"

    zone_breakdown = [
        OTZonePostureOut(
            zone_id=zone.id,
            name=zone.name,
            kind=zone.kind,
            purdue_level=zone.purdue_level,
            devices=zone_counts.get(zone.id, {}).get("devices", 0),
            safety_critical=zone_counts.get(zone.id, {}).get("safety_critical", 0),
        )
        for zone in sorted(zones, key=lambda item: (item.purdue_level is None, item.purdue_level or 0, item.name))
    ]

    return OTPostureOut(
        ot_devices_total=total,
        ot_devices_zoned=zoned,
        unzoned_devices=unzoned,
        safety_critical_devices=safety_critical,
        monitored_devices=monitored,
        unmonitored_devices=unmonitored,
        zones_total=zones_total,
        conduits_total=conduits_total,
        purdue_documented_zones=purdue_documented,
        zone_coverage_pct=zone_coverage,
        conduit_coverage_pct=conduit_coverage,
        posture_level=posture_level,
        iec62443={
            "sr_1_1_zones_defined": zones_total,
            "sr_1_1_conduits_defined": conduits_total,
            "sr_1_2_zoned_assets": zoned,
            "sr_1_2_unzoned_assets": unzoned,
            "sr_2_1_authorized_devices": total,
            "sr_3_1_communication_control": conduits_total > 0,
            "purdue_model_documented": zones_total > 0 and purdue_documented == zones_total,
            "monitoring_coverage_pct": monitored_pct,
            "unmonitored_devices": unmonitored,
            "safety_critical_devices": safety_critical,
        },
        zone_breakdown=zone_breakdown,
    )


def open_vulnerability_count(db: Session, org_id: UUID, asset_id: UUID) -> int:
    return int(
        db.execute(
            select(func.count())
            .select_from(Vulnerability)
            .where(
                Vulnerability.org_id == org_id,
                Vulnerability.asset_id == asset_id,
                Vulnerability.status.in_(["open", "reopened"]),
            )
        ).scalar_one()
    )


def protocol_is_known(value: str) -> bool:
    return ot_protocol_spec(value) is not None


def unzoned_asset_ids(db: Session, org_id: UUID) -> list[UUID]:
    rows = db.execute(
        select(Asset.id)
        .join(OTDevice, OTDevice.asset_id == Asset.id)
        .where(
            Asset.org_id == org_id,
            OTDevice.zone_id.is_(None),
            Asset.zone_id.is_(None),
        )
    ).scalars()
    return list(rows)


__all__ = [
    "DetectionOutcome",
    "MIN_BASELINE_SAMPLES",
    "STALE_AFTER",
    "effective_zone_id",
    "get_ot_device",
    "learn_and_detect",
    "locate_ot_asset",
    "open_vulnerability_count",
    "posture",
    "protocol_catalogue",
    "protocol_is_known",
    "risk_flags",
    "serialize_device",
    "unzoned_asset_ids",
]
