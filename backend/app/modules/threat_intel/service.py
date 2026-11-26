"""Threat intelligence business logic: imports, feeds, enrichment and MITRE data."""

from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass, field
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import quote
from uuid import UUID

from sqlalchemy import func, or_, select, text
from sqlalchemy.orm import Session

from app.core.audit import redact
from app.core.config import settings
from app.core.crypto import decrypt_secret
from app.core.db import utcnow
from app.core.deps import RequestContext
from app.core.errors import NotFound, ServiceUnavailable, ValidationFailure
from app.models.connectors import Connector
from app.models.events import SecurityEvent
from app.models.ti import ThreatActor, ThreatIndicator, TIFeed
from app.modules.threat_intel.stix import (
    DEFAULT_CONFIDENCE,
    INDICATOR_TYPES,
    SEVERITIES,
    StixError,
    StixIndicatorRecord,
    confidence_to_severity,
    guess_indicator_type,
    normalize_value,
    parse_bundle,
    parse_stix_datetime,
)
from app.services.connectors.base import ConnectorError
from app.services.connectors.http import auth_headers, request_json

MAX_IMPORT_RECORDS = 1000
MAX_FEED_OBJECTS = 2000
MAX_FEED_PAGES = 10
MAX_FEED_ERRORS = 50
FEED_TIMEOUT_SECONDS = 20.0

DATA_DIR = Path(__file__).resolve().parents[2] / "data"
MITRE_FILE = DATA_DIR / "mitre_techniques.json"

_SEVERITY_ORDER = {name: index for index, name in enumerate(SEVERITIES)}

_MISP_TYPE_MAP = {
    "ip-src": "ip",
    "ip-dst": "ip",
    "ip": "ip",
    "domain": "domain",
    "hostname": "domain",
    "domain|ip": "domain",
    "url": "url",
    "link": "url",
    "uri": "url",
    "sha256": "sha256",
    "sha1": "sha1",
    "md5": "md5",
    "email-src": "email",
    "email-dst": "email",
}

_MISP_THREAT_LEVELS = {1: "high", 2: "medium", 3: "low", 4: "medium"}


@dataclass
class IndicatorUpsert:
    indicator_type: str
    value: str
    confidence: int = DEFAULT_CONFIDENCE
    severity: str = "medium"
    source: str = "manual"
    description: str | None = None
    tags: list[str] = field(default_factory=list)
    actor_id: UUID | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    expires_at: datetime | None = None
    stix: dict[str, Any] = field(default_factory=dict)


@dataclass
class UpsertSummary:
    created: int = 0
    updated: int = 0
    skipped: int = 0
    errors: list[dict[str, Any]] = field(default_factory=list)

    @property
    def total(self) -> int:
        return self.created + self.updated + self.skipped


# --------------------------------------------------------------------------- #
# MITRE ATT&CK catalogue
# --------------------------------------------------------------------------- #
@lru_cache(maxsize=1)
def load_mitre_techniques() -> tuple[dict[str, Any], ...]:
    """Load the curated ATT&CK subset once; the file is code-shipped and trusted."""
    try:
        raw = json.loads(MITRE_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:  # pragma: no cover - packaging failure
        raise RuntimeError("MITRE technique catalogue is missing or invalid") from exc
    items = raw.get("techniques") if isinstance(raw, dict) else raw
    if not isinstance(items, list):  # pragma: no cover - defensive
        raise RuntimeError("MITRE technique catalogue has an unexpected shape")
    techniques: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        technique_id = str(item.get("id", "")).strip().upper()
        name = str(item.get("name", "")).strip()
        if not technique_id or not name:
            continue
        tactics = [str(tactic).strip().lower() for tactic in item.get("tactics", []) if str(tactic).strip()]
        techniques.append(
            {
                "id": technique_id,
                "name": name,
                "tactics": tactics,
                "description": str(item.get("description", "")).strip(),
            }
        )
    return tuple(techniques)


def mitre_catalog() -> dict[str, dict[str, Any]]:
    return {item["id"]: item for item in load_mitre_techniques()}


# --------------------------------------------------------------------------- #
# Fetching helpers
# --------------------------------------------------------------------------- #
def get_indicator(db: Session, org_id: UUID, indicator_id: UUID, *, include_global: bool = True) -> ThreatIndicator:
    indicator = db.get(ThreatIndicator, indicator_id)
    if indicator is None:
        raise NotFound("Indicator")
    allowed = indicator.org_id == org_id or (include_global and indicator.org_id is None)
    if not allowed:
        raise NotFound("Indicator")
    return indicator


def get_actor(db: Session, org_id: UUID, actor_id: UUID) -> ThreatActor:
    actor = db.get(ThreatActor, actor_id)
    if actor is None or (actor.org_id is not None and actor.org_id != org_id):
        raise NotFound("Threat actor")
    return actor


def get_feed(db: Session, org_id: UUID, feed_id: UUID) -> TIFeed:
    feed = db.get(TIFeed, feed_id)
    if feed is None or feed.org_id != org_id:
        raise NotFound("Feed")
    return feed


def resolve_actor_id(db: Session, org_id: UUID, actor_id: UUID | None) -> UUID | None:
    if actor_id is None:
        return None
    return get_actor(db, org_id, actor_id).id


def _severity_max(current: str, incoming: str) -> str:
    return incoming if _SEVERITY_ORDER.get(incoming, 0) > _SEVERITY_ORDER.get(current, 0) else current


def _merge_tags(existing: list[str], incoming: list[str]) -> list[str]:
    merged = list(existing or [])
    for tag in incoming or []:
        if tag and tag not in merged:
            merged.append(tag)
    return merged[:20]


def upsert_indicators(
    db: Session,
    org_id: UUID,
    records: list[IndicatorUpsert],
    *,
    actor_id: UUID | None = None,
) -> UpsertSummary:
    """Idempotent upsert keyed on (org, indicator_type, value)."""
    summary = UpsertSummary()
    if not records:
        return summary
    if len(records) > MAX_IMPORT_RECORDS:
        raise ValidationFailure(
            [{"field": "records", "message": f"At most {MAX_IMPORT_RECORDS} indicators per import"}]
        )

    deduped: list[IndicatorUpsert] = []
    seen: set[tuple[str, str]] = set()
    for record in records:
        try:
            value = normalize_value(record.indicator_type, record.value)
        except StixError as exc:
            summary.skipped += 1
            summary.errors.append({"field": "value", "message": str(exc)})
            continue
        key = (record.indicator_type, value)
        if key in seen:
            summary.skipped += 1
            continue
        seen.add(key)

        confidence = max(0, min(100, int(record.confidence)))
        severity = record.severity if record.severity in SEVERITIES else confidence_to_severity(confidence)
        deduped.append(
            IndicatorUpsert(
                indicator_type=record.indicator_type,
                value=value,
                confidence=confidence,
                severity=severity,
                source=(record.source or "manual")[:120],
                description=(record.description or None),
                tags=_clean_record_tags(record.tags),
                actor_id=record.actor_id or actor_id,
                first_seen=record.first_seen,
                last_seen=record.last_seen,
                expires_at=record.expires_at,
                stix=record.stix or {},
            )
        )

    if not deduped:
        return summary

    values = {record.value for record in deduped}
    existing_rows = db.execute(
        select(ThreatIndicator).where(ThreatIndicator.org_id == org_id, ThreatIndicator.value.in_(values))
    ).scalars()
    existing = {(row.indicator_type, row.value): row for row in existing_rows}

    now = utcnow()
    for record in deduped:
        row = existing.get((record.indicator_type, record.value))
        if row is None:
            expires_at = record.expires_at
            active = not (expires_at is not None and expires_at <= now)
            item = ThreatIndicator(
                org_id=org_id,
                indicator_type=record.indicator_type,
                value=record.value,
                confidence=record.confidence,
                severity=record.severity,
                source=record.source,
                description=record.description,
                tags=record.tags,
                actor_id=record.actor_id,
                first_seen=record.first_seen or now,
                last_seen=record.last_seen or now,
                expires_at=expires_at,
                active=active,
                stix=record.stix,
            )
            db.add(item)
            summary.created += 1
            continue

        row.confidence = max(row.confidence, record.confidence)
        row.severity = _severity_max(row.severity, record.severity)
        row.tags = _merge_tags(row.tags, record.tags)
        row.last_seen = max(row.last_seen, record.last_seen or now)
        if record.description and not row.description:
            row.description = record.description
        if record.actor_id and not row.actor_id:
            row.actor_id = record.actor_id
        if record.expires_at is not None:
            row.expires_at = record.expires_at
        if record.stix:
            merged_stix = dict(row.stix or {})
            merged_stix.update(record.stix)
            row.stix = merged_stix
        if row.expires_at is not None and row.expires_at <= now:
            row.active = False
        elif row.expires_at is None or row.expires_at > now:
            row.active = True
        summary.updated += 1

    return summary


def _clean_record_tags(values: list[str] | None) -> list[str]:
    cleaned: list[str] = []
    for item in values or []:
        if not isinstance(item, str):
            continue
        tag = item.strip()[:40]
        if tag and tag not in cleaned:
            cleaned.append(tag)
    return cleaned[:20]


# --------------------------------------------------------------------------- #
# STIX / CSV import
# --------------------------------------------------------------------------- #
def records_from_stix(bundle: Any, *, source: str = "stix") -> list[StixIndicatorRecord]:
    try:
        return parse_bundle(bundle)
    except StixError as exc:
        raise ValidationFailure([{"field": "bundle", "message": str(exc)}]) from exc


def stix_records_to_upserts(records: list[StixIndicatorRecord], *, source: str) -> list[IndicatorUpsert]:
    return [
        IndicatorUpsert(
            indicator_type=record.indicator_type,
            value=record.value,
            confidence=record.confidence,
            severity=record.severity,
            source=source[:120],
            description=record.description,
            tags=list(record.labels),
            first_seen=record.valid_from,
            last_seen=None,
            expires_at=record.valid_until,
            stix=record.stix,
        )
        for record in records
    ]


def parse_csv_records(raw: str, *, default_source: str = "csv") -> tuple[list[IndicatorUpsert], UpsertSummary]:
    """Parse a bounded CSV payload with strict per-row validation."""
    summary = UpsertSummary()
    if not isinstance(raw, str) or not raw.strip():
        raise ValidationFailure([{"field": "csv", "message": "CSV payload is empty"}])
    if len(raw) > 2_000_000:
        raise ValidationFailure([{"field": "csv", "message": "CSV payload exceeds 2 MB"}])

    try:
        reader = csv.DictReader(io.StringIO(raw))
        rows = list(reader)
    except csv.Error as exc:
        raise ValidationFailure([{"field": "csv", "message": f"Malformed CSV: {exc}"}]) from exc
    if not reader.fieldnames:
        raise ValidationFailure([{"field": "csv", "message": "CSV must have a header row"}])

    required = {"type", "value"}
    header = {name.strip().lower() for name in reader.fieldnames if name}
    missing = required - header
    if missing:
        raise ValidationFailure(
            [{"field": "csv", "message": f"CSV is missing required columns: {', '.join(sorted(missing))}"}]
        )
    if len(rows) > MAX_IMPORT_RECORDS:
        raise ValidationFailure([{"field": "csv", "message": f"At most {MAX_IMPORT_RECORDS} rows per import"}])

    records: list[IndicatorUpsert] = []
    for index, row in enumerate(rows, start=2):
        normalized_row = {(key or "").strip().lower(): (value or "").strip() for key, value in row.items()}
        indicator_type = normalized_row.get("type", "").lower()
        value = normalized_row.get("value", "")
        if indicator_type not in INDICATOR_TYPES:
            summary.skipped += 1
            summary.errors.append({"row": index, "field": "type", "message": "Unsupported indicator type"})
            continue
        try:
            normalized_value = normalize_value(indicator_type, value)
        except StixError as exc:
            summary.skipped += 1
            summary.errors.append({"row": index, "field": "value", "message": str(exc)})
            continue

        raw_confidence = normalized_row.get("confidence")
        confidence = DEFAULT_CONFIDENCE
        if raw_confidence:
            try:
                confidence = max(0, min(100, int(raw_confidence)))
            except ValueError:
                summary.skipped += 1
                summary.errors.append({"row": index, "field": "confidence", "message": "Confidence must be an integer"})
                continue
        severity = normalized_row.get("severity", "").lower()
        if severity and severity not in SEVERITIES:
            summary.skipped += 1
            summary.errors.append(
                {"row": index, "field": "severity", "message": f"Severity must be one of {', '.join(SEVERITIES)}"}
            )
            continue
        if not severity:
            severity = confidence_to_severity(confidence)
        tags = [tag.strip() for tag in normalized_row.get("tags", "").split("|") if tag.strip()]
        records.append(
            IndicatorUpsert(
                indicator_type=indicator_type,
                value=normalized_value,
                confidence=confidence,
                severity=severity,
                source=(normalized_row.get("source") or default_source)[:120],
                description=normalized_row.get("description") or None,
                tags=tags,
            )
        )
    return records, summary


# --------------------------------------------------------------------------- #
# Feed synchronization
# --------------------------------------------------------------------------- #
def _join_url(base: str, suffix: str) -> str:
    return f"{base.rstrip('/')}/{suffix.lstrip('/')}"


def _feed_credentials(db: Session, feed: TIFeed) -> tuple[str, dict[str, str], bool, dict[str, Any]]:
    """Resolve base URL, auth headers and TLS policy from a connector or feed config."""
    config = dict(feed.config or {})
    url = str(config.get("url") or config.get("base_url") or "").strip()
    verify_tls = bool(config.get("verify_tls", True))
    headers: dict[str, str] = {}
    auth_type = str(config.get("auth_type") or "bearer")
    secret = config.get("api_key") or config.get("token")
    if isinstance(config.get("headers"), dict):
        for key, value in list(config["headers"].items())[:10]:
            header_name = str(key)[:80]
            if header_name.lower() in {"host", "content-length", "transfer-encoding", "connection"}:
                continue
            headers[header_name] = str(value)[:500]
    username = config.get("username")
    password = config.get("password")

    if feed.connector_id:
        connector = db.get(Connector, feed.connector_id)
        if connector is None or connector.org_id != feed.org_id:
            raise NotFound("Connector")
        if connector.base_url and not url:
            url = connector.base_url
        verify_tls = connector.verify_tls
        auth_type = connector.auth_type
        if connector.secret_encrypted:
            try:
                secret = decrypt_secret(connector.secret_encrypted)
            except ValueError as exc:
                raise ServiceUnavailable("Connector secret cannot be decrypted") from exc
        headers.update(auth_headers(secret if isinstance(secret, str) else None, auth_type, connector.config))

    if settings.is_production:
        # Never downgrade transport security in production, even if the stored
        # feed configuration was written in a development environment.
        if not url.startswith("https://"):
            raise ValidationFailure([{"field": "config.url", "message": "Feeds must use HTTPS in production"}])
        verify_tls = True

    if isinstance(secret, str) and secret:
        if auth_type == "bearer" and "Authorization" not in headers:
            headers["Authorization"] = f"Bearer {secret}"
        elif auth_type == "api_key_header" and "X-API-Key" not in headers:
            headers["X-API-Key"] = secret
        elif auth_type == "token_header" and "Authorization" not in headers:
            headers["Authorization"] = secret
        elif auth_type == "basic" and "Authorization" not in headers and username:
            import base64

            headers["Authorization"] = "Basic " + base64.b64encode(f"{username}:{password or ''}".encode()).decode()
    elif isinstance(username, str) and username and "Authorization" not in headers:
        import base64

        headers["Authorization"] = "Basic " + base64.b64encode(f"{username}:{password or ''}".encode()).decode()

    return url, headers, verify_tls, config


def _bounded_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, parsed))


def _taxii_records(
    base_url: str,
    headers: dict[str, str],
    config: dict[str, Any],
    verify_tls: bool,
    added_after: str | None,
    errors: list[dict[str, Any]],
) -> list[IndicatorUpsert]:
    taxii_headers = {
        "Accept": "application/taxii+json;version=2.1",
        "Content-Type": "application/taxii+json;version=2.1",
        **headers,
    }
    collection_ids: list[str] = []
    configured_collection = config.get("collection_id")
    if isinstance(configured_collection, str) and configured_collection.strip():
        collection_ids = [configured_collection.strip()]
    else:
        listing = request_json("GET", _join_url(base_url, "collections/"), headers=taxii_headers, verify_tls=verify_tls)
        collections = listing.data.get("collections") if isinstance(listing.data, dict) else None
        if isinstance(collections, list):
            for item in collections[:5]:
                if isinstance(item, dict) and isinstance(item.get("id"), str):
                    collection_ids.append(item["id"])
    if not collection_ids:
        errors.append({"field": "collection_id", "message": "TAXII server returned no collections"})
        return []

    records: list[IndicatorUpsert] = []
    total_objects = 0
    for collection_id in collection_ids:
        next_token: str | None = None
        for _page in range(MAX_FEED_PAGES):
            params: dict[str, Any] = {"limit": 200}
            if added_after:
                params["added_after"] = added_after
            if next_token:
                params = {"next": next_token}
            response = request_json(
                "GET",
                _join_url(base_url, f"collections/{quote(collection_id, safe='')}/objects/"),
                headers=taxii_headers,
                params=params,
                verify_tls=verify_tls,
                timeout=FEED_TIMEOUT_SECONDS,
            )
            payload = response.data if isinstance(response.data, dict) else {}
            objects = payload.get("objects")
            if not isinstance(objects, list):
                errors.append({"field": "objects", "message": "TAXII envelope missing objects array"})
                break
            if len(objects) > MAX_FEED_OBJECTS:
                objects = objects[:MAX_FEED_OBJECTS]
            total_objects += len(objects)
            if objects:
                bundle = {"type": "bundle", "objects": objects}
                try:
                    stix_items = parse_bundle(bundle)
                except StixError as exc:
                    errors.append({"field": "objects", "message": str(exc)})
                else:
                    records.extend(stix_records_to_upserts(stix_items, source="taxii"))
            next_token = payload.get("next") if isinstance(payload.get("next"), str) else None
            if not next_token or total_objects >= MAX_FEED_OBJECTS:
                break
        if total_objects >= MAX_FEED_OBJECTS:
            break
    return records[:MAX_IMPORT_RECORDS]


def _misp_records(
    base_url: str,
    headers: dict[str, str],
    config: dict[str, Any],
    verify_tls: bool,
    errors: list[dict[str, Any]],
) -> list[IndicatorUpsert]:
    limit = _bounded_int(config.get("limit", 500), 500, 1, 1000)
    response = request_json(
        "POST",
        _join_url(base_url, "attributes/restSearch"),
        headers={"Accept": "application/json", **headers},
        json_body={"returnFormat": "json", "limit": limit, "to_ids": 1},
        verify_tls=verify_tls,
        timeout=FEED_TIMEOUT_SECONDS,
    )
    payload = response.data if isinstance(response.data, dict) else {}
    container = payload.get("response")
    attributes = container.get("Attribute") if isinstance(container, dict) else None
    if not isinstance(attributes, list):
        errors.append({"field": "response", "message": "MISP response missing Attribute list"})
        return []

    records: list[IndicatorUpsert] = []
    default_severity = str(config.get("default_severity") or "") or None
    for attribute in attributes[:MAX_IMPORT_RECORDS]:
        if not isinstance(attribute, dict):
            continue
        indicator_type = _MISP_TYPE_MAP.get(str(attribute.get("type", "")).lower())
        if indicator_type is None:
            continue
        value = attribute.get("value")
        if not isinstance(value, str):
            continue
        confidence = 85 if attribute.get("to_ids") in (True, 1, "1") else 55
        severity = default_severity or _MISP_THREAT_LEVELS.get(
            _bounded_int(attribute.get("threat_level_id"), 2, 1, 4), "medium"
        )
        tags: list[str] = []
        misp_tags = attribute.get("Tag")
        if isinstance(misp_tags, list):
            for tag in misp_tags[:20]:
                if isinstance(tag, dict) and isinstance(tag.get("name"), str):
                    tags.append(tag["name"][:40])
        comment = attribute.get("comment")
        first_seen = parse_stix_datetime(attribute.get("first_seen") or attribute.get("timestamp"))
        records.append(
            IndicatorUpsert(
                indicator_type=indicator_type,
                value=value,
                confidence=confidence,
                severity=severity if severity in SEVERITIES else "medium",
                source="misp",
                description=comment.strip()[:2000] if isinstance(comment, str) and comment.strip() else None,
                tags=tags,
                first_seen=first_seen,
                stix={"misp": {"id": str(attribute.get("id", ""))[:80]}},
            )
        )
    return records


def _opencti_records(
    base_url: str,
    headers: dict[str, str],
    config: dict[str, Any],
    verify_tls: bool,
    errors: list[dict[str, Any]],
) -> list[IndicatorUpsert]:
    limit = _bounded_int(config.get("limit", 200), 200, 1, 500)
    query = (
        "query HispanshieldIndicators($first: Int) { indicators(first: $first) { edges { node { "
        "id name pattern pattern_type confidence valid_from valid_until x_opencti_score } } } }"
    )
    response = request_json(
        "POST",
        _join_url(base_url, "graphql"),
        headers={"Accept": "application/json", **headers},
        json_body={"query": query, "variables": {"first": limit}},
        verify_tls=verify_tls,
        timeout=FEED_TIMEOUT_SECONDS,
    )
    payload = response.data if isinstance(response.data, dict) else {}
    if isinstance(payload.get("errors"), list) and payload["errors"]:
        errors.append({"field": "graphql", "message": "OpenCTI returned GraphQL errors"})
        return []
    data = payload.get("data")
    container = data.get("indicators") if isinstance(data, dict) else None
    edges = container.get("edges") if isinstance(container, dict) else None
    if not isinstance(edges, list):
        errors.append({"field": "data", "message": "OpenCTI response missing indicator edges"})
        return []

    records: list[IndicatorUpsert] = []
    for edge in edges[:MAX_IMPORT_RECORDS]:
        node = edge.get("node") if isinstance(edge, dict) else None
        if not isinstance(node, dict):
            continue
        pattern = node.get("pattern")
        if not isinstance(pattern, str):
            continue
        try:
            parsed = parse_bundle(
                {
                    "type": "bundle",
                    "objects": [{"type": "indicator", "pattern": pattern, "confidence": node.get("confidence")}],
                }
            )
        except StixError:
            continue
        valid_from = parse_stix_datetime(node.get("valid_from"))
        valid_until = parse_stix_datetime(node.get("valid_until"))
        for item in parsed:
            records.append(
                IndicatorUpsert(
                    indicator_type=item.indicator_type,
                    value=item.value,
                    confidence=item.confidence,
                    severity=item.severity,
                    source="opencti",
                    description=str(node.get("name"))[:2000] if node.get("name") else None,
                    tags=[],
                    first_seen=valid_from,
                    expires_at=valid_until,
                    stix={"opencti": {"id": str(node.get("id", ""))[:120]}},
                )
            )
    return records


def _stix_feed_records(
    url: str,
    headers: dict[str, str],
    verify_tls: bool,
    errors: list[dict[str, Any]],
) -> list[IndicatorUpsert]:
    response = request_json(
        "GET",
        url,
        headers={"Accept": "application/stix+json;version=2.1", **headers},
        verify_tls=verify_tls,
        timeout=FEED_TIMEOUT_SECONDS,
    )
    try:
        items = parse_bundle(response.data)
    except StixError as exc:
        errors.append({"field": "bundle", "message": str(exc)})
        return []
    return stix_records_to_upserts(items, source="stix-feed")


def _csv_feed_records(
    url: str,
    headers: dict[str, str],
    verify_tls: bool,
) -> tuple[list[IndicatorUpsert], UpsertSummary]:
    response = request_json(
        "GET",
        url,
        headers={"Accept": "text/csv", **headers},
        verify_tls=verify_tls,
        timeout=FEED_TIMEOUT_SECONDS,
        expect_json=False,
    )
    body = response.data.get("body") if isinstance(response.data, dict) else None
    if not isinstance(body, str):
        raise ValidationFailure([{"field": "body", "message": "CSV feed returned no text body"}])
    return parse_csv_records(body, default_source="csv-feed")


def sync_feed(db: Session, ctx: RequestContext, feed: TIFeed) -> dict[str, Any]:
    """Fetch a feed, upsert indicators and persist health/last-error state."""
    started_at = utcnow()
    url, headers, verify_tls, config = _feed_credentials(db, feed)
    if not url:
        raise ValidationFailure(
            [{"field": "config.url", "message": "A feed URL or linked connector base_url is required"}]
        )

    errors: list[dict[str, Any]] = []
    summary = UpsertSummary()
    objects_read = 0
    added_after = config.get("added_after")
    if not isinstance(added_after, str) or not added_after:
        added_after = feed.last_sync_at.isoformat() if feed.last_sync_at else None

    try:
        if feed.kind == "taxii":
            records = _taxii_records(url, headers, config, verify_tls, added_after, errors)
            objects_read = len(records)
            summary = upsert_indicators(db, feed.org_id, records)
        elif feed.kind == "misp":
            records = _misp_records(url, headers, config, verify_tls, errors)
            objects_read = len(records)
            summary = upsert_indicators(db, feed.org_id, records)
        elif feed.kind == "opencti":
            records = _opencti_records(url, headers, config, verify_tls, errors)
            objects_read = len(records)
            summary = upsert_indicators(db, feed.org_id, records)
        elif feed.kind == "stix":
            records = _stix_feed_records(url, headers, verify_tls, errors)
            objects_read = len(records)
            summary = upsert_indicators(db, feed.org_id, records)
        elif feed.kind == "csv":
            records, parse_summary = _csv_feed_records(url, headers, verify_tls)
            objects_read = len(records) + parse_summary.skipped
            summary = upsert_indicators(db, feed.org_id, records)
            summary.skipped += parse_summary.skipped
            summary.errors.extend(parse_summary.errors)
        else:  # pragma: no cover - schema restricts kind
            raise ValidationFailure([{"field": "kind", "message": "Unsupported feed kind"}])
    except (ConnectorError, StixError, ValidationFailure, ValueError) as exc:
        message = exc.message if isinstance(exc, ValidationFailure) else str(exc)
        feed.status = "error"
        feed.last_sync_at = started_at
        feed.last_error = message[:1000]
        ctx.audit(
            action="ti.feed.sync",
            resource_type="ti_feed",
            resource_id=str(feed.id),
            outcome="failure",
            payload={"kind": feed.kind, "error": feed.last_error},
        )
        db.commit()
        raise ServiceUnavailable(f"Feed synchronization failed: {feed.last_error[:300]}") from exc

    feed.last_sync_at = started_at
    feed.status = "error" if errors and not summary.total else "success"
    feed.last_error = "; ".join(str(item.get("message", ""))[:200] for item in errors[:5]) or None
    if feed.kind == "taxii" and not errors:
        config = dict(feed.config or {})
        config["added_after"] = started_at.isoformat()
        feed.config = config

    result = {
        "feed_id": feed.id,
        "status": feed.status,
        "objects_read": objects_read,
        "created": summary.created,
        "updated": summary.updated,
        "skipped": summary.skipped,
        "errors": errors[:MAX_FEED_ERRORS],
        "last_sync_at": feed.last_sync_at,
    }
    ctx.audit(
        action="ti.feed.sync",
        resource_type="ti_feed",
        resource_id=str(feed.id),
        outcome="success" if feed.status == "success" else "failure",
        payload={
            "kind": feed.kind,
            "objects_read": objects_read,
            "created": summary.created,
            "updated": summary.updated,
            "skipped": summary.skipped,
            "error_count": len(errors),
        },
    )
    db.commit()
    return result


def serialize_feed(feed: TIFeed) -> dict[str, Any]:
    """Feed view with secret-bearing config keys redacted."""
    return {
        "id": feed.id,
        "org_id": feed.org_id,
        "name": feed.name,
        "kind": feed.kind,
        "connector_id": feed.connector_id,
        "enabled": feed.enabled,
        "schedule_minutes": feed.schedule_minutes,
        "last_sync_at": feed.last_sync_at,
        "status": feed.status,
        "last_error": feed.last_error,
        "config": redact(dict(feed.config or {})),
        "created_at": feed.created_at,
        "updated_at": feed.updated_at,
    }


# --------------------------------------------------------------------------- #
# Enrichment
# --------------------------------------------------------------------------- #
def enrich_value(db: Session, org_id: UUID, value: str, indicator_type: str | None = None) -> dict[str, Any]:
    """Match a value against tenant + global indicators without fabricating data."""
    candidates: list[tuple[str, str]] = []
    if indicator_type:
        if indicator_type not in INDICATOR_TYPES:
            raise ValidationFailure([{"field": "type", "message": "Unsupported indicator type"}])
        try:
            candidates.append((indicator_type, normalize_value(indicator_type, value)))
        except StixError as exc:
            raise ValidationFailure([{"field": "value", "message": str(exc)}]) from exc
    else:
        guessed = guess_indicator_type(value)
        if guessed is None:
            raise ValidationFailure([{"field": "value", "message": "Value is not a recognisable indicator"}])
        candidates.append((guessed, normalize_value(guessed, value)))

    now = utcnow()
    matched: list[ThreatIndicator] = []
    for candidate_type, candidate_value in candidates:
        rows = db.execute(
            select(ThreatIndicator).where(
                or_(ThreatIndicator.org_id == org_id, ThreatIndicator.org_id.is_(None)),
                ThreatIndicator.indicator_type == candidate_type,
                ThreatIndicator.value == candidate_value,
                ThreatIndicator.active.is_(True),
                or_(ThreatIndicator.expires_at.is_(None), ThreatIndicator.expires_at > now),
            )
        ).scalars()
        matched.extend(rows)

    if not matched:
        return {
            "value": value,
            "type": indicator_type,
            "verdict": "unknown",
            "confidence": 0,
            "matches": [],
            "actors": [],
            "techniques": [],
            "evidence": [],
            "matched": False,
        }

    actor_ids = {item.actor_id for item in matched if item.actor_id}
    actors = list(db.execute(select(ThreatActor).where(ThreatActor.id.in_(actor_ids))).scalars()) if actor_ids else []
    actor_map = {actor.id: actor for actor in actors}
    catalog = mitre_catalog()

    technique_ids: list[str] = []
    for actor in actors:
        for technique in actor.techniques or []:
            if technique not in technique_ids:
                technique_ids.append(technique)
    for item in matched:
        for tag in item.tags or []:
            candidate = str(tag).strip().upper()
            if candidate.startswith("T") and candidate[1:5].isdigit() and candidate not in technique_ids:
                technique_ids.append(candidate)

    techniques = [
        {**catalog[technique]}
        if technique in catalog
        else {"id": technique, "name": technique, "tactics": [], "description": ""}
        for technique in technique_ids[:50]
    ]

    max_confidence = max(item.confidence for item in matched)
    malicious = max_confidence >= 70 or any(item.severity == "critical" for item in matched)

    evidence = [
        {
            "indicator_id": str(item.id),
            "indicator_type": item.indicator_type,
            "value": item.value,
            "confidence": item.confidence,
            "severity": item.severity,
            "source": item.source,
            "active": item.active,
            "first_seen": item.first_seen,
            "last_seen": item.last_seen,
            "expires_at": item.expires_at,
            "actor_id": str(item.actor_id) if item.actor_id else None,
            "scope": "global" if item.org_id is None else "organization",
        }
        for item in matched[:50]
    ]

    primary_actor = next((actor_map[item.actor_id] for item in matched if item.actor_id in actor_map), None)
    match_columns: dict[str, list[Any]] = {
        "ip": [SecurityEvent.src_ip, SecurityEvent.dst_ip],
        "domain": [SecurityEvent.domain],
        "url": [SecurityEvent.url],
        "sha256": [SecurityEvent.file_hash_sha256],
        "email": [SecurityEvent.user_name],
    }
    operational_events: list[dict[str, Any]] = []
    for matched_type, columns in match_columns.items():
        target = next((item for item in matched if item.indicator_type == matched_type), None)
        if target is not None:
            operational_events = recent_event_matches(db, org_id, target.value, columns)
            break

    return {
        "value": value,
        "type": matched[0].indicator_type if indicator_type is None else indicator_type,
        "verdict": "malicious" if malicious else "suspicious",
        "confidence": max_confidence,
        "matches": evidence,
        "matched": True,
        "events": operational_events,
        "actors": [
            {
                "id": str(actor.id),
                "name": actor.name,
                "aliases": actor.aliases,
                "mitre_id": actor.mitre_id,
                "techniques": actor.techniques,
            }
            for actor in actors
        ],
        "actor": {
            "id": str(primary_actor.id),
            "name": primary_actor.name,
            "aliases": primary_actor.aliases,
            "mitre_id": primary_actor.mitre_id,
        }
        if primary_actor
        else None,
        "techniques": techniques,
        "evidence": evidence,
        "reason": (
            f"Matched {len(matched)} active indicator(s); maximum confidence {max_confidence}."
            if malicious
            else f"Matched {len(matched)} active indicator(s) with confidence below the malicious threshold."
        ),
    }


# --------------------------------------------------------------------------- #
# MITRE coverage and tenant summary
# --------------------------------------------------------------------------- #
def mitre_coverage(db: Session, org_id: UUID) -> dict[str, Any]:
    event_counts = {
        str(technique): int(count)
        for technique, count in db.execute(
            text(
                "SELECT t.value, count(*) FROM security_events, "
                "jsonb_array_elements_text(mitre_techniques) AS t(value) "
                "WHERE org_id = :org GROUP BY t.value"
            ),
            {"org": org_id},
        ).all()
    }
    indicator_counts = {
        str(technique): int(count)
        for technique, count in db.execute(
            text(
                "SELECT t.value, count(*) FROM threat_indicators, "
                "jsonb_array_elements_text(tags) AS t(value) "
                "WHERE org_id = :org GROUP BY t.value"
            ),
            {"org": org_id},
        ).all()
    }
    actor_rows = list(
        db.execute(select(ThreatActor).where(or_(ThreatActor.org_id == org_id, ThreatActor.org_id.is_(None)))).scalars()
    )
    actor_counts: dict[str, int] = {}
    for actor in actor_rows:
        for technique in actor.techniques or []:
            actor_counts[technique] = actor_counts.get(technique, 0) + 1

    catalog = load_mitre_techniques()
    covered: list[dict[str, Any]] = []
    for technique in catalog:
        technique_id = technique["id"]
        events = event_counts.get(technique_id, 0)
        indicators = indicator_counts.get(technique_id, 0)
        actors = actor_counts.get(technique_id, 0)
        if events or indicators or actors:
            covered.append(
                {
                    **technique,
                    "event_count": events,
                    "indicator_count": indicators,
                    "actor_count": actors,
                }
            )
    covered.sort(key=lambda item: (-(item["event_count"] + item["indicator_count"]), item["id"]))
    covered_ids = {entry["id"] for entry in covered}
    total = len(catalog)
    return {
        "catalog_size": total,
        "covered_count": len(covered),
        "coverage_percent": round((len(covered) / total) * 100, 1) if total else 0.0,
        "techniques": covered,
        "uncovered": [item for item in catalog if item["id"] not in covered_ids],
    }


def tenant_summary(db: Session, org_id: UUID) -> dict[str, Any]:
    now = utcnow()

    def _count(stmt) -> int:  # type: ignore[no-untyped-def]
        return int(db.execute(stmt).scalar_one())

    scope = or_(ThreatIndicator.org_id == org_id, ThreatIndicator.org_id.is_(None))
    total_indicators = _count(select(func.count()).select_from(ThreatIndicator).where(scope))
    active_indicators = _count(
        select(func.count())
        .select_from(ThreatIndicator)
        .where(
            scope,
            ThreatIndicator.active.is_(True),
            or_(ThreatIndicator.expires_at.is_(None), ThreatIndicator.expires_at > now),
        )
    )
    expired_indicators = _count(
        select(func.count())
        .select_from(ThreatIndicator)
        .where(scope, ThreatIndicator.expires_at.is_not(None), ThreatIndicator.expires_at <= now)
    )
    by_type = {
        str(key): int(value)
        for key, value in db.execute(
            select(ThreatIndicator.indicator_type, func.count()).where(scope).group_by(ThreatIndicator.indicator_type)
        ).all()
    }
    by_severity = {
        str(key): int(value)
        for key, value in db.execute(
            select(ThreatIndicator.severity, func.count()).where(scope).group_by(ThreatIndicator.severity)
        ).all()
    }
    actor_count = _count(
        select(func.count())
        .select_from(ThreatActor)
        .where(or_(ThreatActor.org_id == org_id, ThreatActor.org_id.is_(None)))
    )
    feeds = list(db.execute(select(TIFeed).where(TIFeed.org_id == org_id).order_by(TIFeed.name)).scalars())
    feed_status: dict[str, int] = {}
    for feed in feeds:
        feed_status[feed.status] = feed_status.get(feed.status, 0) + 1
    coverage = mitre_coverage(db, org_id)
    return {
        "generated_at": now,
        "indicators": {
            "total": total_indicators,
            "active": active_indicators,
            "expired": expired_indicators,
            "inactive": total_indicators - active_indicators,
            "by_type": by_type,
            "by_severity": by_severity,
        },
        "actors": {"total": actor_count},
        "feeds": {
            "total": len(feeds),
            "by_status": feed_status,
            "enabled": sum(1 for feed in feeds if feed.enabled),
            "stale": [
                {"id": str(feed.id), "name": feed.name, "last_sync_at": feed.last_sync_at}
                for feed in feeds
                if feed.enabled
                and (
                    feed.last_sync_at is None
                    or (now - feed.last_sync_at).total_seconds() > feed.schedule_minutes * 60 * 2
                )
            ],
        },
        "mitre": {
            "catalog_size": coverage["catalog_size"],
            "covered_count": coverage["covered_count"],
            "coverage_percent": coverage["coverage_percent"],
        },
        "data_quality": "ok",
    }


def recent_event_matches(db: Session, org_id: UUID, value: str, columns: list[Any]) -> list[dict[str, Any]]:
    """Read-only evidence of operational matches for an indicator value."""
    conditions = [column == value for column in columns]
    if not conditions:
        return []
    rows = db.execute(
        select(SecurityEvent)
        .where(SecurityEvent.org_id == org_id, or_(*conditions))
        .order_by(SecurityEvent.occurred_at.desc())
        .limit(20)
    ).scalars()
    return [
        {
            "event_id": str(event.id),
            "event_uid": event.event_uid,
            "occurred_at": event.occurred_at,
            "severity_id": event.severity_id,
            "message": event.message[:200],
        }
        for event in rows
    ]


__all__ = [
    "IndicatorUpsert",
    "UpsertSummary",
    "enrich_value",
    "get_actor",
    "get_feed",
    "get_indicator",
    "load_mitre_techniques",
    "mitre_catalog",
    "mitre_coverage",
    "parse_csv_records",
    "records_from_stix",
    "recent_event_matches",
    "resolve_actor_id",
    "serialize_feed",
    "stix_records_to_upserts",
    "sync_feed",
    "tenant_summary",
    "upsert_indicators",
]
