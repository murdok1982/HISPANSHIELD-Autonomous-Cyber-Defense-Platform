"""Vendor payload normalization into OCSF-aligned events and STIX indicators.

Everything crossing this boundary is untrusted: strings are stripped of control
characters and bounded, nested structures are truncated, and identifiers are
hashed to stable dedupe keys. Normalizers never raise on a malformed record;
they return ``None`` instead so one bad alert cannot abort a whole sync.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any

from app.core.crypto import sha256_hex
from app.core.db import utcnow

MAX_MESSAGE = 2000
MAX_IDENTIFIER = 200
MAX_VALUE = 500
MAX_TAGS = 20
MAX_MITRE = 20
MAX_RAW_STRING = 2000

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]+")
_ANSI_SEQUENCE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_WHITESPACE = re.compile(r"\s+")
_STIX_PATTERN = re.compile(r"\[(?P<object>[a-zA-Z0-9_-]+(?::[a-zA-Z0-9_.'-]+)?)\s*=\s*'(?P<value>[^']{1,500})'\]")

# OCSF category / class identifiers used by the event fabric.
CATEGORY_FINDINGS = 2
CATEGORY_NETWORK = 4
CLASS_DETECTION_FINDING = 2004
CLASS_NETWORK_ACTIVITY = 4001

SEVERITY_UNKNOWN = 0
SEVERITY_INFO = 1
SEVERITY_LOW = 2
SEVERITY_MEDIUM = 3
SEVERITY_HIGH = 4
SEVERITY_CRITICAL = 5
SEVERITY_FATAL = 6

_TEXT_SEVERITY = {
    "unknown": SEVERITY_UNKNOWN,
    "none": SEVERITY_INFO,
    "info": SEVERITY_INFO,
    "informational": SEVERITY_INFO,
    "notice": SEVERITY_INFO,
    "low": SEVERITY_LOW,
    "minor": SEVERITY_LOW,
    "warning": SEVERITY_LOW,
    "warn": SEVERITY_LOW,
    "medium": SEVERITY_MEDIUM,
    "moderate": SEVERITY_MEDIUM,
    "error": SEVERITY_HIGH,
    "high": SEVERITY_HIGH,
    "severe": SEVERITY_HIGH,
    "major": SEVERITY_HIGH,
    "critical": SEVERITY_CRITICAL,
    "fatal": SEVERITY_FATAL,
    "emergency": SEVERITY_FATAL,
}

_MISP_TYPE_MAP = {
    "ip": "ip",
    "ip-src": "ip",
    "ip-dst": "ip",
    "ip-src|port": "ip",
    "ip-dst|port": "ip",
    "domain": "domain",
    "hostname": "domain",
    "domain|ip": "domain",
    "url": "url",
    "link": "url",
    "uri": "url",
    "sha256": "sha256",
    "sha1": "sha1",
    "md5": "md5",
    "email": "email",
    "email-src": "email",
    "email-dst": "email",
    "filename": "filename",
    "ja3-fingerprint-md5": "ja3",
}

_STIX_OBJECT_MAP = {
    "ipv4-addr": "ip",
    "ipv6-addr": "ip",
    "domain-name": "domain",
    "hostname": "domain",
    "url": "url",
    "email-addr": "email",
    "file:hashes.'sha-256'": "sha256",
    "file:hashes.'sha256'": "sha256",
    "file:hashes.sha-256": "sha256",
    "file:hashes.sha256": "sha256",
    "file:hashes.'sha-1'": "sha1",
    "file:hashes.md5": "md5",
    "directory": "path",
}


def sanitize_text(value: Any, *, limit: int = MAX_MESSAGE) -> str | None:
    """Collapse control characters/whitespace and truncate an untrusted string."""
    if value is None:
        return None
    if isinstance(value, dict | list | tuple):
        try:
            value = json.dumps(value, default=str, ensure_ascii=False)
        except (TypeError, ValueError):
            value = str(value)
    text = _ANSI_SEQUENCE.sub("", str(value))
    text = _CONTROL_CHARS.sub(" ", text)
    text = _WHITESPACE.sub(" ", text).strip()
    if not text:
        return None
    if len(text) > limit:
        return text[: max(0, limit - 1)] + "…"
    return text


def sanitize_identifier(value: Any, *, limit: int = MAX_IDENTIFIER) -> str | None:
    return sanitize_text(value, limit=limit)


def sanitize_mapping(
    value: Any,
    *,
    depth: int = 0,
    max_depth: int = 6,
    max_items: int = 50,
    max_string: int = MAX_RAW_STRING,
) -> Any:
    """Bound and sanitize arbitrary vendor JSON before persisting it as ``raw``."""
    if depth >= max_depth:
        return "[truncated]"
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= max_items:
                result["_truncated_keys"] = len(value) - max_items
                break
            safe_key = sanitize_text(key, limit=80) or f"field_{index}"
            result[safe_key] = sanitize_mapping(
                item, depth=depth + 1, max_depth=max_depth, max_items=max_items, max_string=max_string
            )
        return result
    if isinstance(value, list | tuple):
        return [
            sanitize_mapping(item, depth=depth + 1, max_depth=max_depth, max_items=max_items, max_string=max_string)
            for item in list(value)[:max_items]
        ]
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int | float):
        return value
    return sanitize_text(value, limit=max_string)


def bounded_items(items: Any, limit: int, *, hard_cap: int = 500) -> list[dict[str, Any]]:
    """Return only dict records, capped by the caller limit and an absolute cap."""
    if not isinstance(items, list):
        return []
    ceiling = max(0, min(limit, hard_cap))
    result: list[dict[str, Any]] = []
    for item in items:
        if isinstance(item, dict):
            result.append(item)
        if len(result) >= ceiling:
            break
    return result


def dedupe_key(*parts: Any) -> str:
    """Stable 64-char key; identical vendor records collapse to one event."""
    return sha256_hex("|".join("" if part is None else str(part) for part in parts))


def severity_from_text(value: Any) -> int:
    if value is None:
        return SEVERITY_UNKNOWN
    if isinstance(value, bool):
        return SEVERITY_MEDIUM if value else SEVERITY_LOW
    if isinstance(value, int | float):
        return _severity_from_number(float(value))
    text = str(value).strip().lower()
    if text.isdigit():
        return _severity_from_number(float(text))
    return _TEXT_SEVERITY.get(text, SEVERITY_UNKNOWN)


def _severity_from_number(value: float) -> int:
    if value >= 10:
        return SEVERITY_CRITICAL
    if value >= 7:
        return SEVERITY_HIGH
    if value >= 4:
        return SEVERITY_MEDIUM
    if value >= 1:
        return SEVERITY_LOW
    return SEVERITY_UNKNOWN


def wazuh_severity(level: Any) -> int:
    try:
        numeric = int(level)
    except (TypeError, ValueError):
        return severity_from_text(level)
    if numeric >= 12:
        return SEVERITY_CRITICAL
    if numeric >= 7:
        return SEVERITY_HIGH
    if numeric >= 4:
        return SEVERITY_MEDIUM
    if numeric >= 1:
        return SEVERITY_LOW
    return SEVERITY_INFO


def suricata_severity(value: Any) -> int:
    try:
        numeric = int(value)
    except (TypeError, ValueError):
        return severity_from_text(value)
    return {1: SEVERITY_HIGH, 2: SEVERITY_MEDIUM, 3: SEVERITY_LOW}.get(numeric, SEVERITY_MEDIUM)


def misp_severity(threat_level: Any) -> int:
    try:
        level = int(threat_level)
    except (TypeError, ValueError):
        level = 4
    return {1: SEVERITY_HIGH, 2: SEVERITY_MEDIUM, 3: SEVERITY_LOW}.get(level, SEVERITY_LOW)


def misp_confidence(threat_level: Any) -> int:
    try:
        level = int(threat_level)
    except (TypeError, ValueError):
        level = 4
    return {1: 90, 2: 75, 3: 60}.get(level, 40)


def opencti_severity(score: Any, confidence: Any = None) -> int:
    try:
        numeric = int(score if score is not None else confidence if confidence is not None else 50)
    except (TypeError, ValueError):
        numeric = 50
    if numeric >= 80:
        return SEVERITY_CRITICAL
    if numeric >= 60:
        return SEVERITY_HIGH
    if numeric >= 40:
        return SEVERITY_MEDIUM
    return SEVERITY_LOW


def _as_int(value: Any, *, minimum: int = 0, maximum: int = 65535) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        numeric = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    if numeric < minimum or numeric > maximum:
        return None
    return numeric


def _first(*values: Any) -> Any:
    for value in values:
        if value is None:
            continue
        if isinstance(value, list):
            if not value:
                continue
            return value[0]
        if isinstance(value, str) and not value.strip():
            continue
        return value
    return None


def _nested(payload: dict[str, Any], path: str) -> Any:
    current: Any = payload
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def _first_nested(payload: dict[str, Any], *paths: str) -> Any:
    for path in paths:
        value = _nested(payload, path)
        if value not in (None, "", [], {}):
            return value
    return None


def parse_timestamp(value: Any, *, default: datetime | None = None) -> datetime:
    """Parse ISO-8601, epoch seconds/milliseconds or Go-style expiry strings."""
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    if isinstance(value, int | float) and not isinstance(value, bool):
        seconds = float(value)
        if seconds > 1e12:
            seconds /= 1000.0
        try:
            return datetime.fromtimestamp(seconds, tz=UTC)
        except (OverflowError, OSError, ValueError):
            return default or utcnow()
    if isinstance(value, str) and value.strip():
        text = value.strip()
        try:
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            parsed = datetime.fromisoformat(text)
            return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)
        except ValueError:
            pass
        try:
            return parse_timestamp(float(text), default=default)
        except (TypeError, ValueError):
            pass
    return default or utcnow()


def _normalize_ip(value: Any) -> str | None:
    text = sanitize_text(value, limit=64)
    return text


def _mitre_list(*values: Any) -> list[str]:
    techniques: list[str] = []
    for value in values:
        if value is None:
            continue
        candidates = value if isinstance(value, list) else [value]
        for candidate in candidates:
            if isinstance(candidate, dict):
                candidate = candidate.get("id") or candidate.get("technique") or candidate.get("external_id")
            text = sanitize_text(candidate, limit=40)
            if text and text not in techniques:
                techniques.append(text)
        if len(techniques) >= MAX_MITRE:
            break
    return techniques[:MAX_MITRE]


def _tags(*values: Any) -> list[str]:
    tags: list[str] = []
    for value in values:
        if value is None:
            continue
        candidates = value if isinstance(value, list) else [value]
        for candidate in candidates:
            if isinstance(candidate, dict):
                candidate = candidate.get("name") or candidate.get("value")
            text = sanitize_text(candidate, limit=80)
            if text and text not in tags:
                tags.append(text)
        if len(tags) >= MAX_TAGS:
            break
    return tags[:MAX_TAGS]


def _event_uid(prefix: str, *parts: Any) -> str:
    digest = dedupe_key(prefix, *parts)
    return f"{prefix}:{digest[:48]}"


def _base_event(
    *,
    connector_name: str | None,
    occurred_at: datetime,
    severity_id: int,
    message: str,
    raw: dict[str, Any],
    normalized: dict[str, Any],
    dedupe: str,
    class_uid: int,
    class_name: str,
    category_uid: int,
    event_uid: str,
    raw_format: str = "json",
) -> dict[str, Any]:
    return {
        "event_uid": event_uid,
        "occurred_at": occurred_at,
        "class_uid": class_uid,
        "class_name": class_name,
        "category_uid": category_uid,
        "activity_id": 1,
        "severity_id": severity_id,
        "status_id": 1,
        "message": message[:MAX_MESSAGE],
        "raw": sanitize_mapping(raw),
        "normalized": sanitize_mapping(normalized),
        "raw_format": raw_format,
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "protocol": None,
        "user_name": None,
        "host_name": None,
        "process_name": None,
        "file_hash_sha256": None,
        "url": None,
        "domain": None,
        "mitre_techniques": [],
        "dedupe_key": dedupe[:64],
        "source_connector": sanitize_text(connector_name, limit=80),
    }


def normalize_wazuh_alert(item: dict[str, Any], *, connector_name: str | None = None) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    rule = item.get("rule") or {}
    agent = item.get("agent") or {}
    data = item.get("data") or {}
    rule_id = _first(rule.get("id"), item.get("rule_id"))
    level = _first(rule.get("level"), item.get("level"))
    occurred = parse_timestamp(_first(item.get("timestamp"), item.get("created_at")))
    message = sanitize_text(_first(rule.get("description"), item.get("full_log"), "Wazuh alert"), limit=MAX_MESSAGE)
    external_id = _first(item.get("id"), item.get("alert_id"))
    src_ip = _normalize_ip(_first(data.get("srcip"), data.get("src_ip"), item.get("srcip")))
    dst_ip = _normalize_ip(_first(data.get("dstip"), data.get("dst_ip"), item.get("dstip")))
    mitre = rule.get("mitre") or {}
    techniques = _mitre_list(mitre.get("id") if isinstance(mitre, dict) else mitre, item.get("mitre"))
    host = sanitize_text(_first(agent.get("name"), item.get("host_name")), limit=255)
    dedupe = (
        dedupe_key("wazuh", external_id)
        if external_id
        else dedupe_key("wazuh", rule_id, occurred.isoformat(), src_ip, message)
    )
    event = _base_event(
        connector_name=connector_name,
        occurred_at=occurred,
        severity_id=wazuh_severity(level),
        message=message or "Wazuh alert",
        raw=item,
        normalized={
            "vendor": "wazuh",
            "rule_id": rule_id,
            "rule_level": level,
            "rule_groups": rule.get("groups"),
            "agent_id": agent.get("id"),
            "agent_ip": agent.get("ip"),
            "location": item.get("location"),
        },
        dedupe=dedupe,
        class_uid=CLASS_DETECTION_FINDING,
        class_name="Detection Finding",
        category_uid=CATEGORY_FINDINGS,
        event_uid=_event_uid("wazuh", external_id or rule_id, occurred.isoformat(), src_ip),
    )
    event.update(
        {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": _as_int(_first(data.get("srcport"), data.get("src_port"))),
            "dst_port": _as_int(_first(data.get("dstport"), data.get("dst_port"))),
            "protocol": sanitize_text(data.get("protocol"), limit=30),
            "host_name": host,
            "user_name": sanitize_text(_first(data.get("srcuser"), data.get("user")), limit=200),
            "process_name": sanitize_text(data.get("process"), limit=255),
            "file_hash_sha256": sanitize_text(data.get("sha256"), limit=64),
            "url": sanitize_text(data.get("url"), limit=2048),
            "domain": sanitize_text(data.get("domain"), limit=255),
            "mitre_techniques": techniques,
        }
    )
    return event


def normalize_elastic_signal(item: dict[str, Any], *, connector_name: str | None = None) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    source = item.get("_source") if isinstance(item.get("_source"), dict) else item
    external_id = _first(item.get("_id"), source.get("event.id"), source.get("@timestamp"))
    kibana_alert = _first_nested(source, "kibana.alert") or {}
    rule = _first_nested(source, "signal.rule") or {}
    rule_name = _first(
        _first_nested(kibana_alert, "rule.name"),
        _first_nested(rule, "name"),
        source.get("rule.name"),
        "Elastic detection alert",
    )
    severity_value = _first(
        _first_nested(kibana_alert, "severity"),
        _first_nested(rule, "severity"),
        source.get("severity"),
    )
    occurred = parse_timestamp(_first(source.get("@timestamp"), kibana_alert.get("start")))
    src_ip = _normalize_ip(_first_nested(source, "source.ip", "client.ip"))
    dst_ip = _normalize_ip(_first_nested(source, "destination.ip", "server.ip"))
    threat = _first_nested(source, "threat") or {}
    techniques = _mitre_list(
        threat.get("technique") if isinstance(threat, dict) else threat,
        _first_nested(kibana_alert, "rule.threat"),
        _first_nested(rule, "threat"),
    )
    message = sanitize_text(rule_name, limit=MAX_MESSAGE)
    dedupe = (
        dedupe_key("elastic", external_id)
        if external_id
        else dedupe_key("elastic", occurred.isoformat(), src_ip, message)
    )
    event = _base_event(
        connector_name=connector_name,
        occurred_at=occurred,
        severity_id=severity_from_text(severity_value),
        message=message or "Elastic detection alert",
        raw=item,
        normalized={
            "vendor": "elastic",
            "rule_id": _first_nested(rule, "rule_id", "id"),
            "rule_name": rule_name,
            "signal_status": _first_nested(kibana_alert, "status"),
            "index": item.get("_index"),
        },
        dedupe=dedupe,
        class_uid=CLASS_DETECTION_FINDING,
        class_name="Detection Finding",
        category_uid=CATEGORY_FINDINGS,
        event_uid=_event_uid("elastic", external_id, occurred.isoformat(), src_ip),
    )
    event.update(
        {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": _as_int(_first_nested(source, "source.port", "client.port")),
            "dst_port": _as_int(_first_nested(source, "destination.port", "server.port")),
            "protocol": sanitize_text(_first_nested(source, "network.transport", "network.protocol"), limit=30),
            "host_name": sanitize_text(_first_nested(source, "host.name", "agent.name"), limit=255),
            "user_name": sanitize_text(_first_nested(source, "user.name", "user.email"), limit=200),
            "process_name": sanitize_text(_first_nested(source, "process.name", "process.executable"), limit=255),
            "file_hash_sha256": sanitize_text(_first_nested(source, "file.hash.sha256"), limit=64),
            "url": sanitize_text(_first_nested(source, "url.full", "url.original"), limit=2048),
            "domain": sanitize_text(_first_nested(source, "dns.question.name", "url.domain"), limit=255),
            "mitre_techniques": techniques,
        }
    )
    return event


def _sentinel_entities(row: dict[str, Any]) -> list[dict[str, Any]]:
    raw_entities = row.get("Entities")
    if isinstance(raw_entities, str):
        try:
            parsed = json.loads(raw_entities)
        except ValueError:
            return []
        return [item for item in parsed if isinstance(item, dict)] if isinstance(parsed, list) else []
    if isinstance(raw_entities, list):
        return [item for item in raw_entities if isinstance(item, dict)]
    return []


def normalize_sentinel_alert(item: dict[str, Any], *, connector_name: str | None = None) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    row = {key: _first(value) if isinstance(value, list) else value for key, value in item.items()}
    entities = _sentinel_entities(row)
    addresses = [
        entity.get("Address") or entity.get("AddressValue")
        for entity in entities
        if str(entity.get("Type", "")).lower() in {"ip", "ipaddress"} or entity.get("Address")
    ]
    hostnames = [
        entity.get("HostName") or entity.get("Name")
        for entity in entities
        if str(entity.get("Type", "")).lower() in {"host", "machine"}
    ]
    accounts = [
        entity.get("AccountName") or entity.get("Name")
        for entity in entities
        if str(entity.get("Type", "")).lower() in {"account", "user"}
    ]
    occurred = parse_timestamp(_first(row.get("TimeGenerated"), row.get("StartTime"), row.get("AlertTime")))
    message = sanitize_text(_first(row.get("AlertName"), row.get("DisplayName"), "Microsoft Sentinel alert"))
    external_id = _first(row.get("SystemAlertId"), row.get("ProviderAlertId"), row.get("AlertName"))
    tactics = _tags(str(row.get("Tactics") or "").split(","))
    techniques = _mitre_list(str(row.get("Techniques") or "").split(","))
    dedupe = (
        dedupe_key("sentinel", external_id)
        if external_id
        else dedupe_key("sentinel", occurred.isoformat(), row.get("CompromisedEntity"), message)
    )
    event = _base_event(
        connector_name=connector_name,
        occurred_at=occurred,
        severity_id=severity_from_text(_first(row.get("AlertSeverity"), row.get("Severity"))),
        message=message or "Microsoft Sentinel alert",
        raw=item,
        normalized={
            "vendor": "microsoft_sentinel",
            "alert_name": row.get("AlertName"),
            "provider": _first(row.get("ProviderName"), row.get("ProductName")),
            "product": row.get("ProductName"),
            "tactics": tactics,
            "compromised_entity": row.get("CompromisedEntity"),
        },
        dedupe=dedupe,
        class_uid=CLASS_DETECTION_FINDING,
        class_name="Detection Finding",
        category_uid=CATEGORY_FINDINGS,
        event_uid=_event_uid("sentinel", external_id, occurred.isoformat(), row.get("CompromisedEntity")),
    )
    event.update(
        {
            "src_ip": _normalize_ip(_first(addresses)),
            "host_name": sanitize_text(_first(hostnames, row.get("CompromisedEntity")), limit=255),
            "user_name": sanitize_text(_first(accounts), limit=200),
            "mitre_techniques": techniques,
        }
    )
    return event


def normalize_suricata_event(item: dict[str, Any], *, connector_name: str | None = None) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    alert = item.get("alert") or {}
    event_type = sanitize_text(item.get("event_type"), limit=40) or "alert"
    occurred = parse_timestamp(item.get("timestamp"))
    signature = _first(alert.get("signature"), item.get("event_type"), "Suricata event")
    metadata = alert.get("metadata") or {}
    techniques = _mitre_list(
        metadata.get("mitre_technique_id") if isinstance(metadata, dict) else None,
        metadata.get("mitre_technique") if isinstance(metadata, dict) else None,
    )
    src_ip = _normalize_ip(item.get("src_ip"))
    dst_ip = _normalize_ip(item.get("dest_ip"))
    external_id = _first(item.get("flow_id"), item.get("community_id"))
    dedupe = (
        dedupe_key("suricata", external_id)
        if external_id
        else dedupe_key("suricata", occurred.isoformat(), src_ip, signature)
    )
    event = _base_event(
        connector_name=connector_name,
        occurred_at=occurred,
        severity_id=suricata_severity(alert.get("severity")),
        message=sanitize_text(signature) or "Suricata event",
        raw=item,
        normalized={
            "vendor": "suricata",
            "event_type": event_type,
            "signature_id": alert.get("signature_id"),
            "category": alert.get("category"),
            "action": alert.get("action"),
            "flow_id": item.get("flow_id"),
        },
        dedupe=dedupe,
        class_uid=CLASS_NETWORK_ACTIVITY,
        class_name="Network Activity",
        category_uid=CATEGORY_NETWORK,
        event_uid=_event_uid("suricata", _first(item.get("flow_id"), item.get("community_id")), occurred.isoformat()),
    )
    event.update(
        {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": _as_int(item.get("src_port")),
            "dst_port": _as_int(item.get("dest_port")),
            "protocol": sanitize_text(item.get("proto"), limit=30),
            "host_name": sanitize_text(item.get("host"), limit=255),
            "domain": sanitize_text(_first_nested(item, "dns.rrname", "tls.sni"), limit=255),
            "url": sanitize_text(_first_nested(item, "http.url", "http.hostname"), limit=2048),
            "mitre_techniques": techniques,
        }
    )
    return event


def normalize_zeek_event(item: dict[str, Any], *, connector_name: str | None = None) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    identifiers = item.get("id") if isinstance(item.get("id"), dict) else {}
    src_ip = _normalize_ip(_first(item.get("id.orig_h"), identifiers.get("orig_h")))
    dst_ip = _normalize_ip(_first(item.get("id.resp_h"), identifiers.get("resp_h")))
    occurred = parse_timestamp(item.get("ts"))
    path = sanitize_text(item.get("_path"), limit=40) or "zeek"
    message = sanitize_text(_first(item.get("msg"), item.get("note"), f"Zeek {path} event"))
    external_id = _first(item.get("uid"), item.get("fuid"))
    dedupe = (
        dedupe_key("zeek", external_id)
        if external_id
        else dedupe_key("zeek", path, occurred.isoformat(), src_ip, message)
    )
    event = _base_event(
        connector_name=connector_name,
        occurred_at=occurred,
        severity_id=severity_from_text(item.get("severity")),
        message=message or f"Zeek {path} event",
        raw=item,
        normalized={
            "vendor": "zeek",
            "log": path,
            "note": item.get("note"),
            "sub": item.get("sub"),
        },
        dedupe=dedupe,
        class_uid=CLASS_NETWORK_ACTIVITY,
        class_name="Network Activity",
        category_uid=CATEGORY_NETWORK,
        event_uid=_event_uid("zeek", _first(item.get("uid"), item.get("fuid")), path, occurred.isoformat()),
    )
    event.update(
        {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": _as_int(_first(item.get("id.orig_p"), identifiers.get("orig_p"))),
            "dst_port": _as_int(_first(item.get("id.resp_p"), identifiers.get("resp_p"))),
            "protocol": sanitize_text(item.get("proto"), limit=30),
            "host_name": sanitize_text(_first(item.get("host"), src_ip), limit=255),
            "user_name": sanitize_text(item.get("user"), limit=200),
            "domain": sanitize_text(_first(item.get("query"), item.get("server_name")), limit=255),
            "url": sanitize_text(item.get("uri"), limit=2048),
        }
    )
    return event


def _indicator(
    *,
    indicator_type: str,
    value: Any,
    confidence: int,
    severity: str,
    source: str,
    description: Any,
    tags: list[str],
    first_seen: datetime,
    last_seen: datetime,
    expires_at: datetime | None,
    stix: dict[str, Any],
    active: bool = True,
) -> dict[str, Any] | None:
    safe_value = sanitize_text(value, limit=MAX_VALUE)
    if not safe_value:
        return None
    return {
        "indicator_type": sanitize_text(indicator_type, limit=30) or "unknown",
        "value": safe_value,
        "confidence": max(0, min(100, int(confidence))),
        "severity": severity,
        "source": sanitize_text(source, limit=120) or "connector",
        "description": sanitize_text(description, limit=MAX_MESSAGE),
        "tags": tags[:MAX_TAGS],
        "first_seen": first_seen,
        "last_seen": last_seen,
        "expires_at": expires_at,
        "active": bool(active),
        "stix": sanitize_mapping(stix),
    }


def normalize_misp_attribute(
    item: dict[str, Any],
    *,
    source: str = "misp",
    connector_name: str | None = None,
) -> dict[str, Any] | None:
    """Map a MISP attribute (optionally wrapped with its event) to an indicator."""
    if not isinstance(item, dict):
        return None
    attribute = item.get("Attribute") if isinstance(item.get("Attribute"), dict) else item
    event_meta = item.get("Event") if isinstance(item.get("Event"), dict) else {}
    misp_type = str(attribute.get("type") or "").strip().lower()
    indicator_type = _MISP_TYPE_MAP.get(misp_type)
    if indicator_type is None:
        return None
    value = attribute.get("value")
    if indicator_type in {"domain", "url", "email"} and isinstance(value, str):
        value = value.strip().lower()
    if indicator_type == "ip" and isinstance(value, str) and "|" in value:
        value = value.split("|", 1)[0]
    first_seen = parse_timestamp(_first(attribute.get("first_seen"), event_meta.get("date")))
    last_seen = parse_timestamp(_first(attribute.get("last_seen"), attribute.get("timestamp"), event_meta.get("date")))
    expires_at = None
    if attribute.get("deleted"):
        return None
    tags = _tags(attribute.get("Tag"), event_meta.get("Tag"))
    return _indicator(
        indicator_type=indicator_type,
        value=value,
        confidence=misp_confidence(event_meta.get("threat_level_id")),
        severity=_severity_label(misp_severity(event_meta.get("threat_level_id"))),
        source=connector_name or source,
        description=_first(attribute.get("comment"), event_meta.get("info")),
        tags=tags,
        first_seen=first_seen,
        last_seen=last_seen,
        expires_at=expires_at,
        stix={
            "type": "indicator",
            "spec_version": "2.1",
            "misp_attribute_uuid": attribute.get("uuid"),
            "misp_event_uuid": event_meta.get("uuid"),
            "pattern": f"[{misp_type or 'unknown'}:value = '{sanitize_text(value, limit=MAX_VALUE)}']",
            "to_ids": attribute.get("to_ids"),
        },
    )


def normalize_opencti_indicator(
    item: dict[str, Any],
    *,
    source: str = "opencti",
    connector_name: str | None = None,
) -> dict[str, Any] | None:
    node = item.get("node") if isinstance(item.get("node"), dict) else item
    if not isinstance(node, dict):
        return None
    pattern = sanitize_text(node.get("pattern"), limit=MAX_VALUE)
    if not pattern:
        return None
    match = _STIX_PATTERN.search(pattern)
    if match is None:
        return None
    stix_object = match.group("object").lower()
    indicator_type = _STIX_OBJECT_MAP.get(stix_object)
    if indicator_type is None and not stix_object.startswith("file:"):
        indicator_type = _STIX_OBJECT_MAP.get(stix_object.split(":", 1)[0])
    if indicator_type is None:
        if stix_object.startswith("file:hashes."):
            indicator_type = "sha256"
        else:
            return None
    labels = node.get("objectLabel") or node.get("labels") or []
    tags = _tags(labels)
    confidence = node.get("confidence")
    score = node.get("x_opencti_score")
    first_seen = parse_timestamp(_first(node.get("valid_from"), node.get("created_at")))
    last_seen = parse_timestamp(_first(node.get("valid_until"), node.get("modified"), node.get("created_at")))
    expires_at = parse_timestamp(node.get("valid_until")) if node.get("valid_until") else None
    return _indicator(
        indicator_type=indicator_type,
        value=match.group("value"),
        confidence=int(confidence) if isinstance(confidence, int | float) else int(score or 50),
        severity=_severity_label(opencti_severity(score, confidence)),
        source=connector_name or source,
        description=_first(node.get("description"), node.get("name")),
        tags=tags,
        first_seen=first_seen,
        last_seen=last_seen,
        expires_at=expires_at,
        stix={
            "type": "indicator",
            "spec_version": "2.1",
            "id": node.get("id"),
            "pattern": pattern,
            "pattern_type": node.get("pattern_type") or "stix",
            "revoked": node.get("revoked", False),
        },
        active=not bool(node.get("revoked")),
    )


def _severity_label(severity_id: int) -> str:
    return {
        SEVERITY_INFO: "informational",
        SEVERITY_LOW: "low",
        SEVERITY_MEDIUM: "medium",
        SEVERITY_HIGH: "high",
        SEVERITY_CRITICAL: "critical",
        SEVERITY_FATAL: "critical",
    }.get(severity_id, "medium")


ALERT_NORMALIZERS = {
    "wazuh": normalize_wazuh_alert,
    "elastic_security": normalize_elastic_signal,
    "microsoft_sentinel": normalize_sentinel_alert,
    "suricata_file": normalize_suricata_event,
    "zeek_file": normalize_zeek_event,
    "microsoft_defender": normalize_sentinel_alert,
}

INDICATOR_NORMALIZERS = {
    "misp": normalize_misp_attribute,
    "opencti": normalize_opencti_indicator,
}


def normalize_alert(
    connector_type: str, item: dict[str, Any], *, connector_name: str | None = None
) -> dict[str, Any] | None:
    normalizer = ALERT_NORMALIZERS.get(connector_type)
    if normalizer is None:
        return None
    try:
        return normalizer(item, connector_name=connector_name)
    except (TypeError, ValueError, KeyError, AttributeError):
        return None


def normalize_indicator(
    connector_type: str, item: dict[str, Any], *, connector_name: str | None = None
) -> dict[str, Any] | None:
    normalizer = INDICATOR_NORMALIZERS.get(connector_type)
    if normalizer is None:
        return None
    try:
        return normalizer(item, connector_name=connector_name)
    except (TypeError, ValueError, KeyError, AttributeError):
        return None


__all__ = [
    "ALERT_NORMALIZERS",
    "INDICATOR_NORMALIZERS",
    "bounded_items",
    "dedupe_key",
    "misp_confidence",
    "normalize_alert",
    "normalize_elastic_signal",
    "normalize_indicator",
    "normalize_misp_attribute",
    "normalize_opencti_indicator",
    "normalize_sentinel_alert",
    "normalize_suricata_event",
    "normalize_wazuh_alert",
    "normalize_zeek_event",
    "opencti_severity",
    "parse_timestamp",
    "sanitize_text",
    "severity_from_text",
    "suricata_severity",
    "wazuh_severity",
]
