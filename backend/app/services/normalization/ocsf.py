"""OCSF 1.1 mapping primitives shared by every log parser.

The stored :class:`~app.models.events.SecurityEvent` keeps the OCSF fields that
are commonly queried as typed columns, while the full structured document is
persisted in ``normalized``.  Parsers MUST route unknown vendor fields through
:func:`make_event` so nothing is dropped silently: they end up under
``normalized["unmapped"]``.
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.core.db import utcnow

SCHEMA_VERSION = "1.1.0"

# OCSF 1.1 classes used by the platform.  ``class_uid -> (category_uid, name)``.
OCSF_CLASSES: dict[int, tuple[int, str]] = {
    1001: (1, "File System Activity"),
    1007: (1, "Process Activity"),
    1008: (1, "Event Log Activity"),
    2004: (2, "Detection Finding"),
    3002: (3, "Authentication"),
    4001: (4, "Network Activity"),
    4002: (4, "HTTP Activity"),
    4003: (4, "DNS Activity"),
    4007: (4, "SSH Activity"),
    6003: (6, "API Activity"),
}

OCSF_CATEGORIES: dict[int, str] = {
    0: "Other",
    1: "System Activity",
    2: "Findings",
    3: "Identity & Access Management",
    4: "Network Activity",
    5: "Discovery",
    6: "Application Activity",
}

# The model stores severity 0..5 (unknown, informational, low, medium, high,
# critical).  OCSF 1.1 also defines 6 = Fatal, which we fold into critical.
SEVERITY_NAMES: dict[int, str] = {
    0: "Unknown",
    1: "Informational",
    2: "Low",
    3: "Medium",
    4: "High",
    5: "Critical",
}

STATUS_NAMES: dict[int, str] = {0: "Unknown", 1: "Success", 2: "Failure"}

_SEVERITY_ALIASES: dict[str, int] = {
    "unknown": 0,
    "unspecified": 0,
    "info": 1,
    "informational": 1,
    "information": 1,
    "debug": 1,
    "trace": 1,
    "low": 2,
    "minor": 2,
    "notice": 2,
    "medium": 3,
    "moderate": 3,
    "warn": 3,
    "warning": 3,
    "high": 4,
    "major": 4,
    "error": 4,
    "critical": 5,
    "crit": 5,
    "fatal": 5,
    "emergency": 5,
    "emerg": 5,
    "alert": 5,
}

_STATUS_ALIASES: dict[str, int] = {
    "unknown": 0,
    "success": 1,
    "succeeded": 1,
    "successful": 1,
    "ok": 1,
    "pass": 1,
    "passed": 1,
    "allowed": 1,
    "allow": 1,
    "accepted": 1,
    "permit": 1,
    "completed": 1,
    "failure": 2,
    "failed": 2,
    "fail": 2,
    "error": 2,
    "denied": 2,
    "deny": 2,
    "blocked": 2,
    "rejected": 2,
    "invalid": 2,
    "timeout": 2,
    "timed_out": 2,
}

_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_WHITESPACE_RE = re.compile(r"[ \t]+")
_HASH_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_URL_RE = re.compile(r"^(?:[a-zA-Z][a-zA-Z0-9+.-]*://|/)")
_DOMAIN_LABEL = r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?"
_DOMAIN_RE = re.compile(rf"^(?:{_DOMAIN_LABEL}\.)*{_DOMAIN_LABEL}\.?$")

MAX_MESSAGE_LENGTH = 20000
MAX_RAW_STRING = 20000
MAX_UNMAPPED_KEYS = 200


def sanitize_text(value: Any, *, max_length: int = MAX_MESSAGE_LENGTH) -> str:
    """Remove control characters and bound length (never return raw control data)."""
    if value is None:
        return ""
    text = str(value)
    text = _CONTROL_RE.sub(" ", text)
    text = _WHITESPACE_RE.sub(" ", text).strip()
    return text[:max_length]


def sanitize_value(value: Any, *, depth: int = 0, max_string: int = MAX_RAW_STRING) -> Any:
    """Recursively sanitize JSON-compatible values, bounding depth and payload size."""
    if depth > 8:
        return "[truncated]"
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        return sanitize_text(value, max_length=max_string)
    if isinstance(value, bytes):
        return f"<{len(value)} bytes>"
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= MAX_UNMAPPED_KEYS:
                result["__truncated__"] = True
                break
            result[sanitize_text(key, max_length=200)] = sanitize_value(item, depth=depth + 1, max_string=max_string)
        return result
    if isinstance(value, list | tuple):
        return [sanitize_value(item, depth=depth + 1, max_string=max_string) for item in list(value)[:200]]
    return sanitize_text(value, max_length=max_string)


def severity_to_id(value: Any) -> int:
    """Map a severity label / OCSF id (0..6) to the platform's 0..5 scale."""
    if value is None or value == "":
        return 0
    if isinstance(value, bool):
        return 1 if value else 0
    if isinstance(value, int | float):
        number = int(value)
        if number < 0:
            return 0
        return 5 if number >= 6 else number
    text = str(value).strip().lower()
    if text.isdigit():
        return severity_to_id(int(text))
    alias = _SEVERITY_ALIASES.get(text)
    return alias if alias is not None else 0


def severity_from_cef(value: Any) -> int:
    """CEF severity is 0..10 (or a textual label)."""
    if isinstance(value, bool):
        return 3
    if isinstance(value, int | float):
        score = max(0, min(10, int(value)))
        if score <= 2:
            return 1
        if score <= 4:
            return 2
        if score <= 6:
            return 3
        if score <= 9:
            return 4
        return 5
    text = str(value or "").strip().lower()
    if text.isdigit():
        return severity_from_cef(int(text))
    if text in {"very-high", "very_high", "very high"}:
        return 5
    return severity_to_id(text)


def severity_from_syslog(severity: int) -> int:
    """Syslog severity (0 emergency .. 7 debug) to OCSF 0..5."""
    mapping = {0: 5, 1: 5, 2: 4, 3: 3, 4: 2, 5: 1, 6: 1, 7: 1}
    return mapping.get(int(severity), 0)


def severity_from_otel(number: Any) -> int:
    """OpenTelemetry SeverityNumber (1..24) to OCSF 0..5."""
    try:
        value = int(number)
    except (TypeError, ValueError):
        return 0
    if value <= 8:
        return 1
    if value <= 12:
        return 1
    if value <= 16:
        return 3
    if value <= 20:
        return 4
    if value <= 24:
        return 5
    return 0


def status_from_value(value: Any) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return 1 if value else 2
    if isinstance(value, int | float):
        number = int(value)
        return number if 0 <= number <= 2 else None
    text = str(value).strip().lower()
    if text.isdigit():
        number = int(text)
        return number if 0 <= number <= 2 else None
    return _STATUS_ALIASES.get(text)


def identify_ip(value: Any) -> str | None:
    """Return a canonical IP address or ``None`` (prevents log injection via IP fields)."""
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def identify_port(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return port if 0 <= port <= 65535 else None


def identify_sha256(value: Any) -> str | None:
    if value is None:
        return None
    candidate = str(value).strip()
    return candidate.lower() if _HASH_RE.match(candidate) else None


def identify_domain(value: Any) -> str | None:
    if value is None:
        return None
    candidate = sanitize_text(value, max_length=255).lower().rstrip(".")
    if not candidate or " " in candidate or "/" in candidate:
        return None
    candidate = candidate[2:] if candidate.startswith("*.") else candidate
    return candidate if _DOMAIN_RE.match(candidate) else None


def identify_url(value: Any) -> str | None:
    if value is None:
        return None
    candidate = sanitize_text(value, max_length=2048)
    if not candidate or " " in candidate or not _URL_RE.match(candidate):
        return None
    return candidate


def parse_timestamp(value: Any, *, default: datetime | None = None) -> datetime:
    """Parse vendor timestamps into timezone-aware UTC.

    Epoch values above ~1e11 are interpreted as milliseconds.  Unparseable
    values fall back to ``default`` (now) rather than crashing an ingest batch.
    """
    fallback = default or utcnow()
    if value is None or value == "":
        return fallback
    if isinstance(value, datetime):
        return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, bool):
        return fallback
    if isinstance(value, int | float):
        return _from_epoch(float(value), fallback)
    text = str(value).strip()
    if not text:
        return fallback
    if re.fullmatch(r"-?\d{9,16}(?:\.\d+)?", text):
        return _from_epoch(float(text), fallback)
    candidate = text.replace("Z", "+00:00").replace("z", "+00:00")
    for attempt in (candidate, candidate.replace(" ", "T", 1)):
        try:
            parsed = datetime.fromisoformat(attempt)
        except ValueError:
            continue
        return parsed.astimezone(UTC) if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    for pattern in ("%Y/%m/%d %H:%M:%S", "%d/%m/%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(text, pattern).replace(tzinfo=UTC)
        except ValueError:
            continue
    return fallback


def _from_epoch(value: float, fallback: datetime) -> datetime:
    if value > 1e11:  # milliseconds
        value = value / 1000.0
    try:
        parsed = datetime.fromtimestamp(value, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return fallback
    if parsed.year < 1990 or parsed > utcnow().replace(year=utcnow().year + 2):
        return fallback
    return parsed


def infer_ocsf_class(
    *,
    class_uid: int | None,
    url: str | None,
    domain: str | None,
    process_name: str | None,
    src_ip: str | None,
    dst_ip: str | None,
    dst_port: int | None,
    message: str,
    action: str | None,
) -> tuple[int, int, str]:
    """Pick an OCSF class when the vendor does not provide one explicitly."""
    if class_uid is not None and class_uid in OCSF_CLASSES:
        category, name = OCSF_CLASSES[class_uid]
        return class_uid, category, name
    text = f"{action or ''} {message}".lower()
    if re.search(r"\b(logon|login|authentication|auth|session|sign[ -]?in)\b", text):
        class_uid = 3002
    elif domain and not url:
        class_uid = 4003
    elif url:
        class_uid = 4002
    elif process_name:
        class_uid = 1007
    elif src_ip and (dst_ip or dst_port is not None):
        class_uid = 4001
    else:
        class_uid = 1008
    category, name = OCSF_CLASSES[class_uid]
    return class_uid, category, name


@dataclass(slots=True)
class NormalizedEvent:
    """A vendor-agnostic event ready to be persisted as ``SecurityEvent``."""

    raw_format: str
    raw: dict[str, Any]
    message: str
    occurred_at: datetime
    class_uid: int
    class_name: str
    category_uid: int
    severity_id: int
    status_id: int | None
    normalized: dict[str, Any]
    event_uid: str
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    user_name: str | None = None
    host_name: str | None = None
    process_name: str | None = None
    file_hash_sha256: str | None = None
    url: str | None = None
    domain: str | None = None
    activity_id: int | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def column_values(self) -> dict[str, Any]:
        return {
            "raw_format": self.raw_format,
            "raw": self.raw,
            "message": self.message,
            "occurred_at": self.occurred_at,
            "class_uid": self.class_uid,
            "class_name": self.class_name,
            "category_uid": self.category_uid,
            "severity_id": self.severity_id,
            "status_id": self.status_id,
            "normalized": self.normalized,
            "event_uid": self.event_uid,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "user_name": self.user_name,
            "host_name": self.host_name,
            "process_name": self.process_name,
            "file_hash_sha256": self.file_hash_sha256,
            "url": self.url,
            "domain": self.domain,
            "activity_id": self.activity_id,
        }


def _clean_optional(value: Any, max_length: int) -> str | None:
    text = sanitize_text(value, max_length=max_length)
    return text or None


def make_event(  # noqa: PLR0913 - explicit field mapping is clearer than an opaque dict
    *,
    raw_format: str,
    raw: dict[str, Any],
    message: Any,
    occurred_at: Any = None,
    severity: Any = None,
    status: Any = None,
    class_uid: int | None = None,
    class_name: str | None = None,
    category_uid: int | None = None,
    activity_id: int | None = None,
    status_id: int | None = None,
    src_ip: Any = None,
    dst_ip: Any = None,
    src_port: Any = None,
    dst_port: Any = None,
    protocol: Any = None,
    user_name: Any = None,
    host_name: Any = None,
    process_name: Any = None,
    file_hash_sha256: Any = None,
    url: Any = None,
    domain: Any = None,
    extra: dict[str, Any] | None = None,
    unmapped: dict[str, Any] | None = None,
    product: str | None = None,
    event_uid: str | None = None,
    structured_data: dict[str, Any] | None = None,
) -> NormalizedEvent:
    """Assemble an OCSF document, sanitizing every untrusted field."""
    when = parse_timestamp(occurred_at)
    text = sanitize_text(message) or "Event"
    action = None
    outcome = None
    if extra:
        action = _clean_optional(extra.get("action"), 200)
        outcome = _clean_optional(extra.get("outcome"), 80)

    normalized_src_ip = identify_ip(src_ip)
    normalized_dst_ip = identify_ip(dst_ip)
    normalized_src_port = identify_port(src_port)
    normalized_dst_port = identify_port(dst_port)
    normalized_url = identify_url(url)
    normalized_domain = identify_domain(domain)
    normalized_hash = identify_sha256(file_hash_sha256)
    protocol_text = _clean_optional(protocol, 30)
    if protocol_text:
        protocol_text = protocol_text.upper()
    user_text = _clean_optional(user_name, 200)
    host_text = _clean_optional(host_name, 255)
    process_text = _clean_optional(process_name, 255)

    if class_uid is not None and class_uid not in OCSF_CLASSES:
        # Preserve vendor-specific class ids instead of silently relabelling them.
        resolved_uid = class_uid
        resolved_category = category_uid if category_uid is not None else 0
        resolved_name = sanitize_text(class_name, max_length=80) if class_name else "Other"
    else:
        resolved_uid, resolved_category, resolved_name = infer_ocsf_class(
            class_uid=class_uid,
            url=normalized_url,
            domain=normalized_domain,
            process_name=process_text,
            src_ip=normalized_src_ip,
            dst_ip=normalized_dst_ip,
            dst_port=normalized_dst_port,
            message=text,
            action=action,
        )

    resolved_severity = severity_to_id(severity)
    resolved_status = status_id if status_id is not None else status_from_value(status)
    if resolved_status is not None:
        resolved_status = max(0, min(2, int(resolved_status)))
    resolved_activity = activity_id
    if resolved_activity is None and resolved_uid == 3002:
        resolved_activity = 1
    if resolved_activity is None and resolved_uid == 4001:
        resolved_activity = 6

    uid = event_uid or str(uuid.uuid4())
    normalized_extra = sanitize_value(extra or {})
    if action:
        normalized_extra["action"] = action
    if outcome:
        normalized_extra["outcome"] = outcome
    if structured_data:
        normalized_extra["structured_data"] = sanitize_value(structured_data)
    normalized_extra = {key: value for key, value in normalized_extra.items() if value not in (None, "", [], {})}

    observables: list[dict[str, Any]] = []
    if normalized_src_ip:
        observables.append({"name": "src_endpoint.ip", "type": "IP Address", "value": normalized_src_ip})
    if normalized_dst_ip:
        observables.append({"name": "dst_endpoint.ip", "type": "IP Address", "value": normalized_dst_ip})
    if user_text:
        observables.append({"name": "actor.user.name", "type": "User Name", "value": user_text})
    if host_text:
        observables.append({"name": "device.hostname", "type": "Hostname", "value": host_text})
    if normalized_hash:
        observables.append({"name": "file.hashes.sha256", "type": "SHA-256", "value": normalized_hash})
    if normalized_url:
        observables.append({"name": "http_request.url", "type": "URL String", "value": normalized_url})
    if normalized_domain:
        observables.append({"name": "dns.query.hostname", "type": "Hostname", "value": normalized_domain})

    normalized: dict[str, Any] = {
        "metadata": {
            "version": SCHEMA_VERSION,
            "product": sanitize_text(product, max_length=120) if product else "unknown",
            "uid": uid,
            "original_time": when.isoformat(),
        },
        "class_uid": resolved_uid,
        "class_name": resolved_name,
        "category_uid": resolved_category,
        "category_name": OCSF_CATEGORIES.get(resolved_category, "Other"),
        "activity_id": resolved_activity,
        "severity_id": resolved_severity,
        "severity": SEVERITY_NAMES[resolved_severity].lower(),
        "status_id": resolved_status,
        "status": STATUS_NAMES.get(resolved_status) if resolved_status is not None else None,
        "time": when.isoformat(),
        "message": text,
        "observables": observables,
        "unmapped": sanitize_value(unmapped or {}),
    }
    src_endpoint = {"ip": normalized_src_ip, "port": normalized_src_port}
    dst_endpoint = {"ip": normalized_dst_ip, "port": normalized_dst_port}
    if any(value is not None for value in src_endpoint.values()):
        normalized["src_endpoint"] = {key: value for key, value in src_endpoint.items() if value is not None}
    if any(value is not None for value in dst_endpoint.values()):
        normalized["dst_endpoint"] = {key: value for key, value in dst_endpoint.items() if value is not None}
    if protocol_text:
        normalized["connection_info"] = {"protocol_name": protocol_text}
    actor: dict[str, Any] = {}
    if user_text:
        actor["user"] = {"name": user_text}
    if process_text:
        actor["process"] = {"name": process_text}
    if actor:
        normalized["actor"] = actor
    if host_text:
        normalized["device"] = {"hostname": host_text}
    if normalized_extra:
        normalized["extra"] = normalized_extra

    return NormalizedEvent(
        raw_format=raw_format,
        raw=sanitize_value(raw),
        message=text,
        occurred_at=when,
        class_uid=resolved_uid,
        class_name=resolved_name,
        category_uid=resolved_category,
        severity_id=resolved_severity,
        status_id=resolved_status,
        normalized=normalized,
        event_uid=uid,
        src_ip=normalized_src_ip,
        dst_ip=normalized_dst_ip,
        src_port=normalized_src_port,
        dst_port=normalized_dst_port,
        protocol=protocol_text,
        user_name=user_text,
        host_name=host_text,
        process_name=process_text,
        file_hash_sha256=normalized_hash,
        url=normalized_url,
        domain=normalized_domain,
        activity_id=resolved_activity,
        extra=normalized_extra,
    )


__all__ = [
    "OCSF_CATEGORIES",
    "OCSF_CLASSES",
    "SCHEMA_VERSION",
    "SEVERITY_NAMES",
    "STATUS_NAMES",
    "NormalizedEvent",
    "identify_domain",
    "identify_ip",
    "identify_port",
    "identify_sha256",
    "identify_url",
    "infer_ocsf_class",
    "make_event",
    "parse_timestamp",
    "sanitize_text",
    "sanitize_value",
    "severity_from_cef",
    "severity_from_otel",
    "severity_from_syslog",
    "severity_to_id",
    "status_from_value",
]
