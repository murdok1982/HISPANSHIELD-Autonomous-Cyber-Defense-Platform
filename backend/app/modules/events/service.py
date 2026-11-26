"""Event ingestion pipeline: sources, OCSF persistence, IOC enrichment, retention."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

from sqlalchemy import delete, or_, select
from sqlalchemy.orm import Session

from app.core.audit import append_audit
from app.core.crypto import (
    constant_time_equals,
    decrypt_secret,
    encrypt_secret,
    generate_token,
    hmac_sha256_hex,
    token_hash,
)
from app.core.db import utcnow
from app.core.errors import NotFound
from app.models.core import Policy
from app.models.events import IngestSource, SecurityEvent
from app.models.ti import ThreatIndicator
from app.services.detection import run_detection
from app.services.normalization import SCHEMA_VERSION, NormalizedEvent, make_event, sanitize_text, sanitize_value

TOKEN_PREFIX = "hs_ing_"
HMAC_PREFIX = "hs_hmac_"
MAX_BODY_BYTES = 1_048_576
INGEST_RATE_LIMIT = 120
INGEST_RATE_WINDOW = 60
RETENTION_POLICY_NAME = "event-retention"
DEFAULT_RETENTION: dict[str, Any] = {
    "hot_days": 90,
    "cold_days": 400,
    "batch_size": 5000,
    "purge_enabled": False,
}
_MITRE_RE = re.compile(r"T\d{4}(?:\.\d{3})?")
_TYPE_ALIASES = {
    "ipv4": "ip",
    "ipv6": "ip",
    "ip": "ip",
    "domain": "domain",
    "hostname": "domain",
    "fqdn": "domain",
    "url": "url",
    "uri": "url",
    "sha256": "sha256",
    "hash": "sha256",
    "file": "sha256",
}


@dataclass(slots=True)
class IngestResult:
    event_ids: list[int] = field(default_factory=list)
    alerts_created: int = 0
    alerts_updated: int = 0
    detection_errors: list[dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Ingest sources
# ---------------------------------------------------------------------------


def generate_source_token() -> tuple[str, str]:
    raw = f"{TOKEN_PREFIX}{generate_token(24)}"
    return raw, token_hash(raw)


def generate_hmac_secret() -> str:
    return f"{HMAC_PREFIX}{generate_token(24)}"


def create_source(
    db: Session,
    *,
    org_id: UUID,
    name: str,
    kind: str,
    parser: str,
    enabled: bool,
    config: dict[str, Any],
    created_by: str | None,
    connector_id: UUID | None = None,
    hmac_secret: str | None = None,
    generate_secret: bool = False,
) -> tuple[IngestSource, str, str | None]:
    raw_token, hashed = generate_source_token()
    secret: str | None = hmac_secret
    if generate_secret and not secret:
        secret = generate_hmac_secret()
    source = IngestSource(
        org_id=org_id,
        name=sanitize_text(name, max_length=160),
        kind=kind,
        parser=parser,
        enabled=enabled,
        token_hash=hashed,
        hmac_secret_encrypted=encrypt_secret(secret) if secret else None,
        connector_id=connector_id,
        config=config,
        event_count=0,
        created_by=created_by,
    )
    db.add(source)
    db.flush()
    return source, raw_token, secret


def rotate_source_token(db: Session, source: IngestSource) -> str:
    raw_token, hashed = generate_source_token()
    source.token_hash = hashed
    db.add(source)
    db.flush()
    return raw_token


def resolve_source_by_token(db: Session, raw_token: str) -> IngestSource | None:
    if not raw_token or len(raw_token) > 200:
        return None
    candidate = raw_token.strip()
    if not re.fullmatch(r"[A-Za-z0-9_\-]+", candidate):
        return None
    return db.execute(select(IngestSource).where(IngestSource.token_hash == token_hash(candidate))).scalar_one_or_none()


def verify_source_signature(source: IngestSource, body: bytes, signature: str | None) -> bool:
    """Constant-time HMAC-SHA256 verification when the source declares a secret."""
    if not source.hmac_secret_encrypted:
        return True
    if not signature:
        return False
    try:
        secret = decrypt_secret(source.hmac_secret_encrypted)
    except ValueError:
        return False
    expected = hmac_sha256_hex(secret, body)
    provided = signature.strip().lower()
    if not provided or len(provided) > 200:
        return False
    return constant_time_equals(expected, provided)


def serialize_source(source: IngestSource) -> dict[str, Any]:
    """Safe representation: token hash and encrypted secret are never exposed."""
    return {
        "id": source.id,
        "org_id": source.org_id,
        "name": source.name,
        "kind": source.kind,
        "parser": source.parser,
        "enabled": source.enabled,
        "connector_id": source.connector_id,
        "config": source.config or {},
        "last_event_at": source.last_event_at,
        "event_count": int(source.event_count or 0),
        "created_by": source.created_by,
        "created_at": source.created_at,
        "updated_at": source.updated_at,
        "has_token": bool(source.token_hash),
        "has_hmac_secret": bool(source.hmac_secret_encrypted),
    }


# ---------------------------------------------------------------------------
# IOC enrichment
# ---------------------------------------------------------------------------


def _url_hostname(url: str | None) -> str | None:
    if not url:
        return None
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    return host.lower().rstrip(".") if host else None


def _indicator_mitre(indicator: ThreatIndicator) -> list[str]:
    techniques: set[str] = set()
    for tag in indicator.tags or []:
        techniques.update(match.upper() for match in _MITRE_RE.findall(str(tag)))
    stix = indicator.stix or {}
    for key in ("x_mitre_techniques", "mitre_techniques", "techniques"):
        values = stix.get(key) if isinstance(stix, dict) else None
        if isinstance(values, list):
            for value in values:
                techniques.update(match.upper() for match in _MITRE_RE.findall(str(value)))
    return sorted(techniques)


def _candidate_iocs(event: SecurityEvent) -> list[tuple[str, str]]:
    candidates: list[tuple[str, str]] = []
    if event.src_ip:
        candidates.append(("ip", event.src_ip))
    if event.dst_ip:
        candidates.append(("ip", event.dst_ip))
    if event.domain:
        candidates.append(("domain", event.domain))
    host = _url_hostname(event.url)
    if host:
        candidates.append(("domain", host))
    if event.url:
        candidates.append(("url", event.url))
    if event.file_hash_sha256:
        candidates.append(("sha256", event.file_hash_sha256))
    return candidates


def enrich_event_with_indicators(db: Session, event: SecurityEvent) -> list[dict[str, Any]]:
    """Match active organization/global indicators against the event observables."""
    candidates = _candidate_iocs(event)
    if not candidates:
        return list(event.ioc_matches or [])
    by_type: dict[str, set[str]] = {}
    query_values: set[str] = set()
    for indicator_type, value in candidates:
        normalized_value = value.lower()
        by_type.setdefault(indicator_type, set()).add(normalized_value)
        query_values.add(value)
        query_values.add(normalized_value)
    now = utcnow()
    indicators = list(
        db.execute(
            select(ThreatIndicator).where(
                ThreatIndicator.active.is_(True),
                or_(ThreatIndicator.org_id == event.org_id, ThreatIndicator.org_id.is_(None)),
                or_(ThreatIndicator.expires_at.is_(None), ThreatIndicator.expires_at > now),
                ThreatIndicator.value.in_(sorted(query_values)[:200]),
            )
        ).scalars()
    )
    matches: dict[str, dict[str, Any]] = {
        str(item.get("indicator_id")): item for item in (event.ioc_matches or []) if isinstance(item, dict)
    }
    techniques = set(event.mitre_techniques or [])
    for indicator in indicators:
        canonical = _TYPE_ALIASES.get(indicator.indicator_type.lower(), indicator.indicator_type.lower())
        if canonical not in by_type:
            continue
        if indicator.value.lower() not in by_type[canonical]:
            continue
        indicator_mitre = _indicator_mitre(indicator)
        matches[str(indicator.id)] = {
            "indicator_id": str(indicator.id),
            "indicator_type": indicator.indicator_type,
            "value": indicator.value,
            "severity": indicator.severity,
            "confidence": indicator.confidence,
            "source": indicator.source,
            "scope": "global" if indicator.org_id is None else "organization",
            "tags": [sanitize_text(tag, max_length=120) for tag in (indicator.tags or [])[:10]],
            "mitre": indicator_mitre,
        }
        techniques.update(indicator_mitre)
        indicator.last_seen = now
        db.add(indicator)
    event.ioc_matches = list(matches.values())
    event.mitre_techniques = sorted(techniques)
    db.add(event)
    return event.ioc_matches


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def _dedupe_key(source_id: UUID | None, parsed: NormalizedEvent) -> str:
    material = json.dumps(
        {
            "source": str(source_id) if source_id else None,
            "message": parsed.message,
            "occurred_at": parsed.occurred_at.isoformat(),
            "raw": parsed.raw,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _record_from_parsed(org_id: UUID, source_id: UUID | None, parsed: NormalizedEvent) -> SecurityEvent:
    values = parsed.column_values()
    return SecurityEvent(
        org_id=org_id,
        source_id=source_id,
        received_at=utcnow(),
        schema_version=SCHEMA_VERSION,
        ioc_matches=[],
        mitre_techniques=[],
        dedupe_key=_dedupe_key(source_id, parsed),
        is_demo=False,
        **values,
    )


def ingest_parsed_events(
    db: Session,
    *,
    org_id: UUID,
    source: IngestSource | None,
    events: list[NormalizedEvent],
    run_pipeline: bool = True,
) -> IngestResult:
    """Persist normalized events, enrich IOCs and run detection in one transaction."""
    if not events:
        return IngestResult()
    records = [_record_from_parsed(org_id, source.id if source else None, parsed) for parsed in events]
    db.add_all(records)
    db.flush()
    for record in records:
        enrich_event_with_indicators(db, record)
    db.flush()

    if source is not None:
        last_seen = max(record.occurred_at for record in records)
        if source.last_event_at is None or last_seen > source.last_event_at:
            source.last_event_at = last_seen
        source.event_count = int(source.event_count or 0) + len(records)
        db.add(source)

    result = IngestResult(event_ids=[record.id for record in records])
    if run_pipeline:
        outcome = run_detection(db, org_id=org_id, events=records)
        result.alerts_created = outcome.alerts_created
        result.alerts_updated = outcome.alerts_updated
        result.detection_errors = outcome.errors
    db.flush()
    return result


def build_manual_event(record: dict[str, Any]) -> NormalizedEvent:
    """Convert a validated authenticated-ingest record into an OCSF event."""
    extra = {
        key: record.get(key)
        for key in ("action", "outcome", "category", "bytes_in", "bytes_out")
        if record.get(key) is not None
    }
    if record.get("normalized"):
        extra["custom_normalized"] = sanitize_value(record["normalized"])
    raw = record.get("raw")
    if not isinstance(raw, dict):
        raw = {
            "format": "manual",
            "record": {
                key: value for key, value in record.items() if key not in {"raw", "normalized"} and value is not None
            },
        }
    parsed = make_event(
        raw_format="json",
        raw=raw,
        message=record.get("message"),
        occurred_at=record.get("occurred_at"),
        severity=record.get("severity"),
        status=record.get("outcome"),
        status_id=record.get("status_id"),
        class_uid=record.get("class_uid"),
        class_name=record.get("class_name"),
        category_uid=record.get("category_uid"),
        activity_id=record.get("activity_id"),
        src_ip=record.get("src_ip"),
        dst_ip=record.get("dst_ip"),
        src_port=record.get("src_port"),
        dst_port=record.get("dst_port"),
        protocol=record.get("protocol"),
        user_name=record.get("user_name"),
        host_name=record.get("host_name"),
        process_name=record.get("process_name"),
        file_hash_sha256=record.get("file_hash_sha256"),
        url=record.get("url"),
        domain=record.get("domain"),
        extra=extra,
        unmapped={},
        product="manual",
    )
    return parsed


def audit_ingest(
    db: Session,
    *,
    org_id: UUID,
    source: IngestSource,
    accepted: int,
    rejected: int,
    outcome: str = "success",
    ip_address: str | None = None,
    user_agent: str | None = None,
    request_id: str | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    payload = {
        "source_name": source.name,
        "source_kind": source.kind,
        "accepted": accepted,
        "rejected": rejected,
    }
    if detail:
        payload["detail"] = detail
    append_audit(
        db,
        org_id=org_id,
        action="event.ingest",
        resource_type="ingest_source",
        resource_id=str(source.id),
        actor_type="source",
        actor_id=str(source.id),
        outcome=outcome,
        payload=payload,
        request_id=request_id,
        ip_address=ip_address,
        user_agent=user_agent,
    )


# ---------------------------------------------------------------------------
# Retention
# ---------------------------------------------------------------------------


def _normalized_retention(definition: dict[str, Any] | None) -> dict[str, Any]:
    merged = {**DEFAULT_RETENTION, **(definition or {})}
    return {
        "hot_days": max(1, min(3650, int(merged.get("hot_days", 90)))),
        "cold_days": max(1, min(4000, int(merged.get("cold_days", 400)))),
        "batch_size": max(100, min(50000, int(merged.get("batch_size", 5000)))),
        "purge_enabled": bool(merged.get("purge_enabled", False)),
    }


def get_retention_policy(db: Session, org_id: UUID) -> tuple[Policy | None, dict[str, Any]]:
    policy = db.execute(
        select(Policy).where(
            Policy.org_id == org_id,
            Policy.kind == "retention",
            Policy.name == RETENTION_POLICY_NAME,
        )
    ).scalar_one_or_none()
    definition = _normalized_retention(policy.definition if policy else None)
    return policy, definition


def serialize_retention(policy: Policy | None, definition: dict[str, Any]) -> dict[str, Any]:
    return {
        "policy_id": policy.id if policy else None,
        "name": RETENTION_POLICY_NAME,
        "kind": "retention",
        "version": policy.version if policy else 0,
        "enabled": policy.enabled if policy else True,
        "definition": definition,
        "effective_cutoff": utcnow() - timedelta(days=definition["hot_days"]),
        "source": "policy" if policy else "default",
        "updated_at": policy.updated_at if policy else None,
    }


def save_retention_policy(
    db: Session,
    *,
    org_id: UUID,
    definition: dict[str, Any],
    actor_id: str | None,
) -> tuple[Policy, dict[str, Any]]:
    normalized = _normalized_retention(definition)
    policy, _ = get_retention_policy(db, org_id)
    if policy is None:
        policy = Policy(
            org_id=org_id,
            name=RETENTION_POLICY_NAME,
            kind="retention",
            version=1,
            enabled=True,
            definition=normalized,
            created_by=actor_id,
            description="Security event retention budget",
        )
        db.add(policy)
    else:
        policy.definition = normalized
        policy.version += 1
        db.add(policy)
    db.flush()
    return policy, normalized


def purge_old_events(
    db: Session,
    *,
    org_id: UUID,
    cutoff: datetime,
    batch_size: int,
    max_batches: int = 20,
) -> tuple[int, int, bool]:
    """Delete events older than ``cutoff`` in bounded batches (never one huge DELETE)."""
    deleted = 0
    batches = 0
    truncated = False
    for _ in range(max_batches):
        ids = list(
            db.execute(
                select(SecurityEvent.id)
                .where(SecurityEvent.org_id == org_id, SecurityEvent.occurred_at < cutoff)
                .order_by(SecurityEvent.id.asc())
                .limit(batch_size)
            ).scalars()
        )
        if not ids:
            break
        db.execute(delete(SecurityEvent).where(SecurityEvent.id.in_(ids)))
        db.flush()
        deleted += len(ids)
        batches += 1
        if len(ids) < batch_size:
            break
    else:
        truncated = True
    return deleted, batches, truncated


def source_or_404(db: Session, org_id: UUID, source_id: UUID) -> IngestSource:
    source = db.get(IngestSource, source_id)
    if source is None or source.org_id != org_id:
        raise NotFound("Ingest source")
    return source


__all__ = [
    "DEFAULT_RETENTION",
    "HMAC_PREFIX",
    "INGEST_RATE_LIMIT",
    "INGEST_RATE_WINDOW",
    "MAX_BODY_BYTES",
    "RETENTION_POLICY_NAME",
    "TOKEN_PREFIX",
    "IngestResult",
    "audit_ingest",
    "build_manual_event",
    "create_source",
    "enrich_event_with_indicators",
    "generate_hmac_secret",
    "generate_source_token",
    "get_retention_policy",
    "ingest_parsed_events",
    "purge_old_events",
    "resolve_source_by_token",
    "rotate_source_token",
    "save_retention_policy",
    "serialize_retention",
    "serialize_source",
    "source_or_404",
    "verify_source_signature",
]
