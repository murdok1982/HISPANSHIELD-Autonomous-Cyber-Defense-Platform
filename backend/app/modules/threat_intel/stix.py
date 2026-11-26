"""Bounded STIX 2.1 pattern parsing and normalization.

Security invariants enforced here:

* No ``eval``/``exec`` and no third-party STIX engine: patterns are matched with a
  bounded regular expression and every extracted indicator is validated by type.
* Pattern length, comparison count and operand length are hard-capped so a hostile
  bundle cannot cause catastrophic backtracking or memory exhaustion.
* Invalid operands (private/loopback IPs are still valid IOCs, but malformed
  addresses are not) are rejected instead of being guessed.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.core.schemas import EMAIL_RE

PATTERN_MAX_LENGTH = 2000
MAX_COMPARISONS = 10
OPERAND_MAX_LENGTH = 500
BUNDLE_MAX_OBJECTS = 5000
BUNDLE_MAX_INDICATORS = 1000
DEFAULT_CONFIDENCE = 50

INDICATOR_TYPES = ("ip", "domain", "url", "sha256", "sha1", "md5", "email")
SEVERITIES = ("low", "medium", "high", "critical")

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
)
_HASH_LENGTHS = {"sha256": 64, "sha1": 40, "md5": 32}
_HEX_RE = re.compile(r"^[a-f0-9]+$")
_PATTERN_COMPARISON_RE = re.compile(
    r"(?P<object>ipv4-addr|ipv6-addr|domain-name|url|email-addr|file)"
    r":(?P<field>[A-Za-z0-9_.'\-]{1,60})"
    r"\s*=\s*"
    r"'(?P<value>[^'\x00]{1,500})'"
)


class StixError(ValueError):
    """Raised when a STIX document or pattern is structurally malformed."""


@dataclass(frozen=True)
class PatternMatch:
    indicator_type: str
    value: str


@dataclass(frozen=True)
class StixIndicatorRecord:
    indicator_type: str
    value: str
    confidence: int
    severity: str
    labels: list[str] = field(default_factory=list)
    description: str | None = None
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    stix: dict[str, Any] = field(default_factory=dict)


def normalize_value(indicator_type: str, value: str) -> str:
    """Validate and canonicalize an indicator value for its declared type."""
    if not isinstance(value, str):
        raise StixError("Indicator value must be a string")
    cleaned = value.strip()
    if not cleaned or len(cleaned) > OPERAND_MAX_LENGTH:
        raise StixError("Indicator value must be between 1 and 500 characters")
    if "\x00" in cleaned or any(ord(char) < 32 for char in cleaned):
        raise StixError("Indicator value contains control characters")

    if indicator_type == "ip":
        try:
            return str(ipaddress.ip_address(cleaned))
        except ValueError as exc:
            raise StixError("Invalid IPv4/IPv6 address") from exc
    if indicator_type == "domain":
        lowered = cleaned.lower().rstrip(".")
        if not _DOMAIN_RE.match(lowered):
            raise StixError("Invalid domain name")
        return lowered
    if indicator_type == "url":
        if len(cleaned) > 500:
            raise StixError("URL exceeds 500 characters")
        lowered = cleaned.lower()
        if not (lowered.startswith("http://") or lowered.startswith("https://")):
            raise StixError("URL must use http or https")
        if re.search(r"[\r\n\t]", cleaned):
            raise StixError("URL contains control characters")
        return cleaned
    if indicator_type in _HASH_LENGTHS:
        lowered = cleaned.lower()
        if len(lowered) != _HASH_LENGTHS[indicator_type] or not _HEX_RE.match(lowered):
            raise StixError(f"Invalid {indicator_type} hash")
        return lowered
    if indicator_type == "email":
        lowered = cleaned.lower()
        if not EMAIL_RE.match(lowered):
            raise StixError("Invalid email address")
        return lowered
    raise StixError(f"Unsupported indicator type: {indicator_type}")


def guess_indicator_type(value: str) -> str | None:
    """Best-effort type detection used only to focus enrichment lookups."""
    for candidate in ("ip", "url", "sha256", "sha1", "md5", "email", "domain"):
        try:
            normalize_value(candidate, value)
        except StixError:
            continue
        return candidate
    return None


def _parse_comparison(match: re.Match[str]) -> PatternMatch | None:
    object_type = match.group("object")
    raw_field = match.group("field").strip()
    value = match.group("value").strip()
    field_lower = raw_field.lower()

    if object_type in {"ipv4-addr", "ipv6-addr"}:
        if field_lower != "value":
            return None
        return PatternMatch("ip", normalize_value("ip", value))
    if object_type == "domain-name":
        if field_lower != "value":
            return None
        return PatternMatch("domain", normalize_value("domain", value))
    if object_type == "url":
        if field_lower != "value":
            return None
        return PatternMatch("url", normalize_value("url", value))
    if object_type == "email-addr":
        if field_lower != "value":
            return None
        return PatternMatch("email", normalize_value("email", value))
    if object_type == "file":
        normalized_field = field_lower.replace('"', "").replace(".", "_")
        hash_map = {
            "hashes_'sha-256'": "sha256",
            "hashes_sha-256": "sha256",
            "hashes_'sha1'": "sha1",
            "hashes_sha1": "sha1",
            "hashes_'md5'": "md5",
            "hashes_md5": "md5",
        }
        indicator_type = hash_map.get(normalized_field)
        if indicator_type is None:
            return None
        return PatternMatch(indicator_type, normalize_value(indicator_type, value))
    return None


def parse_pattern(pattern: str) -> list[PatternMatch]:
    """Extract bounded comparisons from a STIX pattern.

    Only simple equality comparisons on well-known indicator properties are
    accepted. Anything else is ignored (never interpreted), and a pattern with no
    usable comparison is rejected so imports do not silently no-op.
    """
    if not isinstance(pattern, str):
        raise StixError("STIX pattern must be a string")
    stripped = pattern.strip()
    if not stripped or len(stripped) > PATTERN_MAX_LENGTH:
        raise StixError("STIX pattern is empty or exceeds the 2000 character limit")
    if not (stripped.startswith("[") and stripped.endswith("]")):
        raise StixError("STIX pattern must be a bracketed observation expression")

    matches = list(_PATTERN_COMPARISON_RE.finditer(stripped))
    if len(matches) > MAX_COMPARISONS:
        raise StixError(f"STIX pattern exceeds {MAX_COMPARISONS} comparisons")

    parsed: list[PatternMatch] = []
    seen: set[tuple[str, str]] = set()
    for match in matches:
        try:
            item = _parse_comparison(match)
        except StixError:
            # A malformed operand invalidates the pattern: never import a guess.
            raise
        if item is None:
            continue
        key = (item.indicator_type, item.value)
        if key not in seen:
            seen.add(key)
            parsed.append(item)
    if not parsed:
        raise StixError("STIX pattern contains no supported indicator comparison")
    return parsed


def parse_stix_datetime(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, int | float):
        # MISP timestamps are Unix epoch seconds; reject implausible values.
        if not 0 <= float(value) <= 4_102_444_800:
            raise StixError("Invalid epoch timestamp")
        return datetime.fromtimestamp(float(value), tz=UTC)
    if not isinstance(value, str) or len(value) > 64:
        raise StixError("Invalid STIX timestamp")
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise StixError("Invalid STIX timestamp") from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def confidence_to_severity(confidence: int) -> str:
    if confidence >= 85:
        return "critical"
    if confidence >= 70:
        return "high"
    if confidence >= 40:
        return "medium"
    return "low"


def _coerce_confidence(value: Any) -> int:
    try:
        confidence = int(value)
    except (TypeError, ValueError):
        return DEFAULT_CONFIDENCE
    return max(0, min(100, confidence))


def _coerce_labels(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    labels: list[str] = []
    for item in value[:20]:
        if isinstance(item, str):
            cleaned = item.strip()[:64]
            if cleaned and cleaned not in labels:
                labels.append(cleaned)
    return labels


def _record_from_indicator_object(obj: dict[str, Any]) -> list[StixIndicatorRecord]:
    pattern = obj.get("pattern")
    if not isinstance(pattern, str):
        raise StixError("STIX indicator object is missing a pattern")
    matches = parse_pattern(pattern)
    confidence = _coerce_confidence(obj.get("confidence", DEFAULT_CONFIDENCE))
    labels = _coerce_labels(obj.get("labels"))
    description_raw = obj.get("description")
    description = description_raw.strip()[:2000] if isinstance(description_raw, str) else None
    name_raw = obj.get("name")
    name = name_raw.strip()[:200] if isinstance(name_raw, str) else None
    valid_from = parse_stix_datetime(obj.get("valid_from"))
    valid_until = parse_stix_datetime(obj.get("valid_until"))
    if valid_from and valid_until and valid_until <= valid_from:
        raise StixError("STIX indicator valid_until must be after valid_from")

    stix_meta: dict[str, Any] = {"pattern": pattern, "pattern_type": obj.get("pattern_type", "stix")}
    if isinstance(obj.get("id"), str):
        stix_meta["id"] = obj["id"][:120]
    if name:
        stix_meta["name"] = name
    external = obj.get("external_references")
    if isinstance(external, list):
        stix_meta["external_references"] = [
            {
                "source_name": str(item.get("source_name"))[:80],
                "external_id": str(item.get("external_id"))[:80],
            }
            for item in external[:10]
            if isinstance(item, dict)
        ]

    records: list[StixIndicatorRecord] = []
    for match in matches:
        record_description = description or name
        records.append(
            StixIndicatorRecord(
                indicator_type=match.indicator_type,
                value=match.value,
                confidence=confidence,
                severity=confidence_to_severity(confidence),
                labels=labels,
                description=record_description,
                valid_from=valid_from,
                valid_until=valid_until,
                stix=stix_meta,
            )
        )
    return records


def parse_bundle(bundle: Any, *, limit: int = BUNDLE_MAX_INDICATORS) -> list[StixIndicatorRecord]:
    """Validate a STIX 2.1 bundle and return deduplicated indicator records."""
    if not isinstance(bundle, dict):
        raise StixError("STIX bundle must be a JSON object")
    if bundle.get("type") != "bundle":
        raise StixError("Document is not a STIX 2.1 bundle")
    objects = bundle.get("objects")
    if not isinstance(objects, list):
        raise StixError("STIX bundle must contain an objects array")
    if len(objects) > BUNDLE_MAX_OBJECTS:
        raise StixError(f"STIX bundle exceeds {BUNDLE_MAX_OBJECTS} objects")

    records: list[StixIndicatorRecord] = []
    seen: set[tuple[str, str]] = set()
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != "indicator":
            continue
        for record in _record_from_indicator_object(obj):
            key = (record.indicator_type, record.value)
            if key in seen:
                continue
            seen.add(key)
            records.append(record)
            if len(records) > limit:
                raise StixError(f"STIX import exceeds the {limit} indicator limit")
    if not records:
        raise StixError("STIX bundle contains no importable indicator objects")
    return records


__all__ = [
    "BUNDLE_MAX_INDICATORS",
    "INDICATOR_TYPES",
    "SEVERITIES",
    "PatternMatch",
    "StixError",
    "StixIndicatorRecord",
    "confidence_to_severity",
    "guess_indicator_type",
    "normalize_value",
    "parse_bundle",
    "parse_pattern",
    "parse_stix_datetime",
]
