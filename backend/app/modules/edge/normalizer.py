"""Internal normalizer for edge telemetry (network / OT / IoT / generic JSON).

The normalizer is deliberately dependency-free and defensive: edge payloads are
untrusted, so every string is length-capped, control characters are stripped,
addresses and ports are validated, and nested JSON is bounded before it reaches
``SecurityEvent.raw``. Unknown fields are ignored rather than reflected.
"""

from __future__ import annotations

import hashlib
import ipaddress
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

MAX_EVENT_DEPTH = 4
MAX_EVENT_KEYS = 64
MAX_EVENT_LIST = 50
MAX_STRING_LENGTH = 1000

_KIND_PROFILE: dict[str, dict[str, Any]] = {
    "network": {"class_uid": 4001, "class_name": "Network Activity", "category_uid": 4},
    "ot": {"class_uid": 9001, "class_name": "Industrial Control Activity", "category_uid": 9},
    "iot": {"class_uid": 9002, "class_name": "IoT Activity", "category_uid": 9},
    "json": {"class_uid": 6003, "class_name": "API Activity", "category_uid": 6},
}

_SEVERITY_IDS = {"info": 1, "informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


def safe_str(value: Any, limit: int = MAX_STRING_LENGTH) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        value = str(value).lower()
    if not isinstance(value, str | int | float):
        return None
    cleaned = "".join(char for char in str(value) if ord(char) >= 32 and ord(char) != 127).strip()
    if not cleaned:
        return None
    return cleaned[:limit]


def bounded_payload(value: Any, depth: int = 0) -> Any:
    """Return a JSON-safe, size-bounded copy of untrusted input."""
    if depth > MAX_EVENT_DEPTH:
        return "[truncated]"
    if isinstance(value, dict):
        bounded: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= MAX_EVENT_KEYS:
                break
            bounded[safe_str(key, 80) or str(index)] = bounded_payload(item, depth + 1)
        return bounded
    if isinstance(value, list | tuple):
        return [bounded_payload(item, depth + 1) for item in list(value)[:MAX_EVENT_LIST]]
    if isinstance(value, dict | bytes):
        return "[binary]"
    if isinstance(value, str | int | float | bool) or value is None:
        return safe_str(value) if isinstance(value, str) else value
    return None


def _safe_ip(value: Any) -> str | None:
    text = safe_str(value, 64)
    if not text:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def _safe_port(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 <= port <= 65535 else None


def _safe_sha256(value: Any) -> str | None:
    text = (safe_str(value, 64) or "").lower()
    if len(text) != 64 or any(char not in "0123456789abcdef" for char in text):
        return None
    return text


def _safe_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, int | float) and not isinstance(value, bool):
        seconds = float(value)
        if seconds > 10_000_000_000:  # milliseconds
            seconds /= 1000.0
        if 0 <= seconds <= 4_102_444_800:
            return datetime.fromtimestamp(seconds, tz=UTC)
        return datetime.now(UTC)
    text = safe_str(value, 64)
    if text:
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return datetime.now(UTC)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    return datetime.now(UTC)


def _severity_id(event: dict[str, Any]) -> int:
    raw = event.get("severity_id")
    if isinstance(raw, int) and 0 <= raw <= 6:
        return raw
    label = (safe_str(event.get("severity"), 20) or "").lower()
    return _SEVERITY_IDS.get(label, 3)


def _techniques(event: dict[str, Any]) -> list[str]:
    raw = event.get("mitre_techniques") or event.get("techniques")
    if not isinstance(raw, list):
        return []
    techniques: list[str] = []
    for item in raw[:20]:
        candidate = (safe_str(item, 20) or "").upper()
        if (
            len(candidate) >= 5
            and candidate.startswith("T")
            and candidate[1:5].isdigit()
            and candidate not in techniques
        ):
            techniques.append(candidate)
    return techniques


def normalize_edge_event(gateway_id: UUID, kind: str, event: dict[str, Any]) -> dict[str, Any]:
    """Map one edge event onto ``SecurityEvent`` constructor kwargs."""
    profile = _KIND_PROFILE.get(kind, _KIND_PROFILE["json"])
    raw_uid = safe_str(event.get("event_uid") or event.get("uid") or event.get("id"), 80)
    canonical = bounded_payload(event)
    if raw_uid is None:
        digest = hashlib.sha256(repr(sorted(canonical.items()) if isinstance(canonical, dict) else canonical).encode())
        raw_uid = f"edge-{digest.hexdigest()[:32]}"

    message = safe_str(event.get("message") or event.get("description"), 4000) or f"{kind} event from edge gateway"
    activity_id = event.get("activity_id")
    return {
        "event_uid": raw_uid,
        "occurred_at": _safe_timestamp(event.get("occurred_at") or event.get("timestamp") or event.get("time")),
        "class_uid": profile["class_uid"],
        "class_name": profile["class_name"],
        "category_uid": profile["category_uid"],
        "activity_id": activity_id if isinstance(activity_id, int) and 0 <= activity_id <= 99 else None,
        "severity_id": _severity_id(event),
        "status_id": 1,
        "message": message,
        "raw": canonical if isinstance(canonical, dict) else {"value": canonical},
        "normalized": {
            "edge_kind": kind,
            "gateway_id": str(gateway_id),
            "event_uid": raw_uid,
        },
        "raw_format": "edge",
        "src_ip": _safe_ip(event.get("src_ip") or event.get("source_ip")),
        "dst_ip": _safe_ip(event.get("dst_ip") or event.get("destination_ip")),
        "src_port": _safe_port(event.get("src_port") or event.get("source_port")),
        "dst_port": _safe_port(event.get("dst_port") or event.get("destination_port")),
        "protocol": safe_str(event.get("protocol"), 30),
        "user_name": safe_str(event.get("user_name") or event.get("user"), 200),
        "host_name": safe_str(event.get("host_name") or event.get("host") or event.get("device"), 255),
        "process_name": safe_str(event.get("process_name") or event.get("process"), 255),
        "file_hash_sha256": _safe_sha256(event.get("file_hash_sha256") or event.get("sha256")),
        "url": safe_str(event.get("url"), 2000),
        "domain": safe_str(event.get("domain"), 255),
        "mitre_techniques": _techniques(event),
    }


def dedupe_key_for(gateway_id: UUID, event_uid: str) -> str:
    return hashlib.sha256(f"edge:{gateway_id}:{event_uid}".encode()).hexdigest()


__all__ = ["bounded_payload", "dedupe_key_for", "normalize_edge_event", "safe_str"]
