"""Real-world log parsers mapped to OCSF 1.1.

Supported formats:

* arbitrary vendor JSON (including nested documents and NDJSON),
* CEF (ArcSight Common Event Format),
* LEEF 1.0 / 2.0 (IBM QRadar),
* syslog RFC 5424 and RFC 3164 (including structured data and embedded CEF),
* OpenTelemetry log records (``resourceLogs`` or a single log record).

Every parser returns :class:`~app.services.normalization.ocsf.NormalizedEvent`
instances.  Fields that are not recognised are preserved under
``normalized["unmapped"]``; malformed input raises :class:`ParseError` so the
ingestion boundary can return a 422 instead of storing junk.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from app.services.normalization.ocsf import (
    NormalizedEvent,
    identify_ip,
    make_event,
    parse_timestamp,
    sanitize_text,
    severity_from_cef,
    severity_from_otel,
    severity_from_syslog,
    severity_to_id,
)

MAX_EVENTS_PER_PAYLOAD = 500

_MONTHS = {
    "jan": 1,
    "feb": 2,
    "mar": 3,
    "apr": 4,
    "may": 5,
    "jun": 6,
    "jul": 7,
    "aug": 8,
    "sep": 9,
    "oct": 10,
    "nov": 11,
    "dec": 12,
}


class ParseError(ValueError):
    """Raised when a payload cannot be parsed safely."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def __str__(self) -> str:
        return self.message


# ---------------------------------------------------------------------------
# Generic field discovery
# ---------------------------------------------------------------------------

JSON_ALIASES: dict[str, list[str]] = {
    "occurred_at": [
        "occurred_at",
        "timestamp",
        "time",
        "@timestamp",
        "eventTime",
        "event_time",
        "ts",
        "datetime",
        "created_at",
        "rt",
        "start",
        "end",
    ],
    "message": [
        "message",
        "msg",
        "event",
        "description",
        "text",
        "log",
        "body",
        "short_message",
        "summary",
        "details",
    ],
    "severity": ["severity_id", "severity", "level", "priority", "sev", "risk_level"],
    "status_id": ["status_id"],
    "status": ["status", "outcome", "result", "disposition"],
    "class_uid": ["class_uid"],
    "activity_id": ["activity_id", "activity"],
    "src_ip": [
        "src_ip",
        "srcip",
        "src",
        "source_ip",
        "sourceIp",
        "saddr",
        "client_ip",
        "ip_src",
        "src_endpoint.ip",
        "source.ip",
        "network.peer.address",
    ],
    "dst_ip": [
        "dst_ip",
        "dstip",
        "dst",
        "destination_ip",
        "destinationIp",
        "daddr",
        "server_ip",
        "ip_dst",
        "dst_endpoint.ip",
        "destination.ip",
        "server.address",
    ],
    "src_port": ["src_port", "sport", "source_port", "sourcePort", "src_endpoint.port", "network.peer.port"],
    "dst_port": [
        "dst_port",
        "dport",
        "destination_port",
        "destinationPort",
        "dst_endpoint.port",
        "server.port",
        "port",
    ],
    "protocol": ["protocol", "proto", "transport", "network.transport", "connection_info.protocol_name"],
    "user_name": [
        "user_name",
        "username",
        "user",
        "suser",
        "account",
        "account_name",
        "actor",
        "principal",
        "identity",
        "actor.user.name",
        "user.name",
        "enduser.id",
    ],
    "host_name": [
        "host_name",
        "hostname",
        "host",
        "computer",
        "device",
        "device_name",
        "shost",
        "dhost",
        "sproc_host",
        "device.hostname",
        "host.name",
    ],
    "process_name": [
        "process_name",
        "process",
        "proc",
        "program",
        "app",
        "application",
        "image",
        "sproc",
        "actor.process.name",
        "process.name",
        "process.executable.name",
    ],
    "file_hash_sha256": [
        "file_hash_sha256",
        "sha256",
        "fileHash",
        "hash_sha256",
        "file.hashes.sha256",
        "hash.sha256",
        "file.hash.sha256",
    ],
    "url": ["url", "requestURL", "request_url", "uri", "http.url", "url.full", "http_request.url"],
    "domain": ["domain", "fqdn", "dns", "query", "domain_name", "dns.query.hostname", "query_name"],
    "action": ["action", "act", "event_type", "eventType"],
    "outcome": ["outcome"],
    "category": ["category", "cat", "log_category"],
    "bytes_in": ["bytes_in", "in_bytes", "bytesIn", "received_bytes", "bytes_received", "in"],
    "bytes_out": ["bytes_out", "out_bytes", "bytesOut", "sent_bytes", "bytes_sent", "out"],
    "external_id": ["external_id", "externalId", "event_id", "event_uid"],
    "product": ["product", "vendor", "source_product"],
    "log_source": ["log_source", "source", "logsource"],
}

_CONSUMED_EXTRA_KEYS = (
    "action",
    "outcome",
    "category",
    "bytes_in",
    "bytes_out",
    "external_id",
    "product",
    "log_source",
)


def _flatten(value: Any, prefix: str = "", out: dict[str, Any] | None = None, depth: int = 0) -> dict[str, Any]:
    if out is None:
        out = {}
    if depth > 6:
        out[f"{prefix or '__root__'}.__depth_truncated__"] = True
        return out
    if isinstance(value, dict):
        for key, item in value.items():
            if len(out) >= 600:
                out["__truncated__"] = True
                break
            path = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(item, dict | list):
                _flatten(item, path, out, depth + 1)
            else:
                out[path] = item
    elif isinstance(value, list | tuple):
        for index, item in enumerate(list(value)[:100]):
            path = f"{prefix}[{index}]"
            if isinstance(item, dict | list):
                _flatten(item, path, out, depth + 1)
            else:
                out[path] = item
    elif prefix:
        out[prefix] = value
    return out


def _lookup(flat: dict[str, Any], aliases: list[str]) -> tuple[str, Any] | None:
    lowered = {path.lower(): path for path in flat}
    for alias in aliases:
        path = lowered.get(alias.lower())
        if path is not None:
            return path, flat[path]
    for alias in aliases:
        target = alias.lower()
        for path, value in flat.items():
            last = re.sub(r"\[\d+\]$", "", path.rsplit(".", 1)[-1]).lower()
            if last == target:
                return path, value
    # Nested vendor envelopes: "event.source.ip" must satisfy "source.ip".
    for alias in aliases:
        target = alias.lower()
        for path, value in flat.items():
            lowered_path = path.lower()
            if lowered_path.endswith(f".{target}"):
                return path, value
    return None


def _take(flat: dict[str, Any], aliases: list[str], consumed: set[str]) -> Any:
    found = _lookup(flat, aliases)
    if found is None:
        return None
    path, value = found
    consumed.add(path)
    return value


def _as_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(float(str(value).strip()))
    except (TypeError, ValueError):
        return None


def _int_or_none(value: Any) -> int | None:
    number = _as_int(value)
    return number if number is not None and 0 <= number <= 99999 else None


def _domain_from_url(url: str | None) -> str | None:
    if not url:
        return None
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    return host.lower().rstrip(".") if host else None


def _event_from_mapping(
    document: dict[str, Any],
    *,
    raw_format: str = "json",
    product: str | None = None,
    occurred_fallback: datetime | None = None,
) -> NormalizedEvent:
    flat = _flatten(document)
    consumed: set[str] = set()

    message = _take(flat, JSON_ALIASES["message"], consumed)
    severity = _take(flat, JSON_ALIASES["severity"], consumed)
    status_value = _take(flat, JSON_ALIASES["status"], consumed)
    status_id = _as_int(_take(flat, JSON_ALIASES["status_id"], consumed))
    src_ip = _take(flat, JSON_ALIASES["src_ip"], consumed)
    dst_ip = _take(flat, JSON_ALIASES["dst_ip"], consumed)
    src_port = _take(flat, JSON_ALIASES["src_port"], consumed)
    dst_port = _take(flat, JSON_ALIASES["dst_port"], consumed)
    protocol = _take(flat, JSON_ALIASES["protocol"], consumed)
    user_name = _take(flat, JSON_ALIASES["user_name"], consumed)
    host_name = _take(flat, JSON_ALIASES["host_name"], consumed)
    process_name = _take(flat, JSON_ALIASES["process_name"], consumed)
    file_hash = _take(flat, JSON_ALIASES["file_hash_sha256"], consumed)
    url = _take(flat, JSON_ALIASES["url"], consumed)
    domain = _take(flat, JSON_ALIASES["domain"], consumed)
    class_uid = _int_or_none(_take(flat, JSON_ALIASES["class_uid"], consumed))
    activity_id = _int_or_none(_take(flat, JSON_ALIASES["activity_id"], consumed))
    occurred_at = _take(flat, JSON_ALIASES["occurred_at"], consumed)

    extra: dict[str, Any] = {}
    for key in _CONSUMED_EXTRA_KEYS:
        if key == "product":
            continue
        value = _take(flat, JSON_ALIASES[key], consumed)
        if value is not None:
            extra[key] = value
    if status_value is not None and "outcome" not in extra:
        extra["outcome"] = status_value
    header_product = _take(flat, JSON_ALIASES["product"], consumed)

    if not domain:
        domain = _domain_from_url(str(url)) if url else None

    unmapped = {path: value for path, value in flat.items() if path not in consumed and path != "__truncated__"}
    if "__truncated__" in flat:
        unmapped["__truncated__"] = True

    return make_event(
        raw_format=raw_format,
        raw=document,
        message=message,
        occurred_at=occurred_at if occurred_at is not None else occurred_fallback,
        severity=severity,
        status=status_value,
        status_id=status_id,
        class_uid=class_uid,
        activity_id=activity_id,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        user_name=user_name,
        host_name=host_name,
        process_name=process_name,
        file_hash_sha256=file_hash,
        url=url,
        domain=domain,
        extra=extra,
        unmapped=unmapped,
        product=product or (str(header_product) if header_product else None),
    )


# ---------------------------------------------------------------------------
# JSON / OpenTelemetry
# ---------------------------------------------------------------------------


def _looks_like_otel(document: dict[str, Any]) -> bool:
    if "resourceLogs" in document:
        return True
    if "severityNumber" in document or "severityText" in document:
        return True
    return (
        "body" in document
        and "attributes" in document
        and not any(key in document for key in ("message", "msg", "src", "dst"))
    )


def _any_value(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    for key in ("stringValue", "intValue", "doubleValue", "boolValue", "bytesValue"):
        if key in value:
            return value[key]
    if "arrayValue" in value:
        raw_values = value.get("arrayValue") or {}
        return [_any_value(item) for item in raw_values.get("values", [])]
    if "kvlistValue" in value:
        raw_values = value.get("kvlistValue") or {}
        return {item.get("key"): _any_value(item.get("value")) for item in raw_values.get("values", [])}
    return value


def _otel_attributes(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return {str(key): _any_value(item) for key, item in value.items()}
    if isinstance(value, list):
        attributes: dict[str, Any] = {}
        for item in value[:200]:
            if isinstance(item, dict) and "key" in item:
                attributes[str(item["key"])] = _any_value(item.get("value"))
        return attributes
    return {}


def _otel_time(record: dict[str, Any]) -> Any:
    for key in ("timeUnixNano", "observedTimeUnixNano"):
        value = record.get(key)
        if value is None:
            continue
        try:
            return datetime.fromtimestamp(int(str(value)) / 1_000_000_000, tz=UTC)
        except (TypeError, ValueError, OSError, OverflowError):
            continue
    return record.get("timestamp") or record.get("time") or record.get("observedTime")


def _otel_body_text(body: Any) -> str:
    if body is None:
        return ""
    if isinstance(body, str):
        return body
    if isinstance(body, dict | list):
        return json.dumps(body, ensure_ascii=False, default=str)
    return str(body)


def _otel_event(
    record: dict[str, Any],
    *,
    resource_attributes: dict[str, Any],
    scope_name: str | None = None,
) -> NormalizedEvent:
    attributes = _otel_attributes(record.get("attributes"))
    consumed: set[str] = set()

    def take(*keys: str) -> Any:
        for key in keys:
            if key in attributes:
                consumed.add(key)
                return attributes[key]
        return None

    body = _any_value(record.get("body"))
    message = _otel_body_text(body)
    severity_text = record.get("severityText")
    severity_number = record.get("severityNumber")
    severity = severity_to_id(severity_text) if severity_text else severity_from_otel(severity_number)

    host_name = take("host.name", "device.hostname", "hostname") or resource_attributes.get("host.name")
    service_name = resource_attributes.get("service.name") or scope_name
    user_name = take("user.name", "enduser.id", "user.id")
    src_ip = take("network.peer.address", "client.address", "net.peer.ip")
    dst_ip = take("server.address", "net.host.ip", "network.local.address")
    src_port = take("network.peer.port")
    dst_port = take("server.port", "network.local.port")
    protocol = take("network.transport")
    process_name = take("process.executable.name", "process.command")
    file_hash = take("file.hash.sha256")
    url = take("http.url", "url.full")
    domain = take("server.address")
    if domain is not None and identify_ip(domain) is not None:
        domain = None
    status_code = take("http.status_code")
    outcome: str | None = None
    if status_code is not None:
        code = _as_int(status_code)
        if code is not None:
            outcome = "success" if code < 400 else "failure"
    event_name = take("event.name")

    extra: dict[str, Any] = {
        "trace_id": record.get("traceId"),
        "span_id": record.get("spanId"),
        "event_name": event_name,
        "service_name": service_name,
        "scope": scope_name,
    }
    if isinstance(body, dict | list):
        extra["body"] = body
    extra = {key: value for key, value in extra.items() if value not in (None, "")}
    unmapped = {f"attribute.{key}": value for key, value in attributes.items() if key not in consumed}
    for key, value in record.items():
        if key in {
            "timeUnixNano",
            "observedTimeUnixNano",
            "severityText",
            "severityNumber",
            "body",
            "attributes",
            "traceId",
            "spanId",
            "timestamp",
            "time",
        }:
            continue
        unmapped[f"record.{key}"] = value

    if not host_name and service_name:
        host_name = service_name
    return make_event(
        raw_format="otel",
        raw={"format": "otel", "record": record, "resource": resource_attributes},
        message=message,
        occurred_at=_otel_time(record),
        severity=severity,
        status=outcome,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        user_name=user_name,
        host_name=host_name,
        process_name=process_name,
        file_hash_sha256=file_hash,
        url=url,
        domain=domain,
        extra=extra,
        unmapped=unmapped,
        product=service_name or "opentelemetry",
    )


def _parse_otel_document(document: Any) -> list[NormalizedEvent]:
    if not isinstance(document, dict):
        raise ParseError("malformed_otel", "OpenTelemetry payload must be a JSON object")
    resource_logs = document.get("resourceLogs")
    if resource_logs is None:
        if "body" in document or "severityNumber" in document or "severityText" in document:
            return [_otel_event(document, resource_attributes={})]
        raise ParseError("malformed_otel", "OpenTelemetry payload has no resourceLogs or log record")
    if not isinstance(resource_logs, list):
        raise ParseError("malformed_otel", "resourceLogs must be a list")

    events: list[NormalizedEvent] = []
    for resource_log in resource_logs:
        if not isinstance(resource_log, dict):
            raise ParseError("malformed_otel", "Each resourceLogs entry must be an object")
        resource = resource_log.get("resource") or {}
        resource_attributes = _otel_attributes(resource.get("attributes")) if isinstance(resource, dict) else {}
        for scope_log in resource_log.get("scopeLogs", []) or []:
            if not isinstance(scope_log, dict):
                raise ParseError("malformed_otel", "Each scopeLogs entry must be an object")
            scope = scope_log.get("scope") or {}
            scope_name = scope.get("name") if isinstance(scope, dict) else None
            for record in scope_log.get("logRecords", []) or []:
                if not isinstance(record, dict):
                    raise ParseError("malformed_otel", "Each log record must be an object")
                events.append(_otel_event(record, resource_attributes=resource_attributes, scope_name=scope_name))
    if not events:
        raise ParseError("empty_payload", "OpenTelemetry payload contains no log records")
    return events


def _reject_json_constant(value: str) -> Any:
    raise ValueError(f"Invalid JSON constant: {value}")


def _loads_json(text: str) -> Any:
    return json.loads(text, parse_constant=_reject_json_constant)


def _parse_json_document(document: Any) -> list[NormalizedEvent]:
    if isinstance(document, list):
        if not document:
            raise ParseError("empty_payload", "JSON payload contains no events")
        if len(document) > MAX_EVENTS_PER_PAYLOAD:
            raise ParseError("too_many_events", f"A payload may contain at most {MAX_EVENTS_PER_PAYLOAD} events")
        events: list[NormalizedEvent] = []
        for item in document:
            if not isinstance(item, dict):
                raise ParseError("malformed_json", "Every event in a JSON array must be an object")
            events.extend(_parse_json_document(item))
        return events
    if not isinstance(document, dict):
        raise ParseError("malformed_json", "JSON payload must be an object or an array of objects")
    if set(document.keys()) == {"events"} and isinstance(document.get("events"), list):
        return _parse_json_document(document["events"])
    if _looks_like_otel(document):
        return _parse_otel_document(document)
    return [_event_from_mapping(document)]


# ---------------------------------------------------------------------------
# CEF
# ---------------------------------------------------------------------------

CEF_EXTENSION_MAP: dict[str, str] = {
    "src": "src_ip",
    "dst": "dst_ip",
    "spt": "src_port",
    "dpt": "dst_port",
    "proto": "protocol",
    "suser": "user_name",
    "dvc": "host_name",
    "dvchost": "host_name",
    "dhost": "host_name",
    "shost": "host_name",
    "sproc": "process_name",
    "app": "process_name",
    "fname": "file_name",
    "filehash": "file_hash_sha256",
    "request": "url",
    "requesturl": "url",
    "msg": "message",
    "rt": "occurred_at",
    "start": "occurred_at",
    "end": "occurred_at",
    "devicereceipttime": "occurred_at",
    "act": "action",
    "cat": "category",
    "outcome": "status",
    "externalid": "external_id",
    "in": "bytes_in",
    "out": "bytes_out",
    "reason": "reason",
    "requestmethod": "request_method",
}

_CUSTOM_KEY_RE = re.compile(r"^(?:cs|cn|devicecustomstring|devicecustomnumber)\d+(?:label)?$", re.IGNORECASE)


def _split_unescaped(value: str, separator: str, maxsplit: int = -1) -> list[str]:
    parts: list[str] = []
    buffer: list[str] = []
    escaped = False
    splits = 0
    for char in value:
        if escaped:
            buffer.append(char)
            escaped = False
        elif char == "\\":
            buffer.append(char)
            escaped = True
        elif char == separator and (maxsplit < 0 or splits < maxsplit):
            parts.append("".join(buffer))
            buffer = []
            splits += 1
        else:
            buffer.append(char)
    parts.append("".join(buffer))
    return parts


def _unescape(value: str) -> str:
    result: list[str] = []
    escaped = False
    for char in value:
        if escaped:
            result.append({"n": "\n", "r": "\r", "t": "\t"}.get(char, char))
            escaped = False
        elif char == "\\":
            escaped = True
        else:
            result.append(char)
    if escaped:
        result.append("\\")
    return "".join(result)


def _parse_extension(value: str) -> dict[str, str]:
    """Split a CEF extension into ``key -> value`` without losing escaped spaces."""
    matches = list(re.finditer(r"(?:^|\s)([A-Za-z0-9_.]+)=", value))
    extension: dict[str, str] = {}
    for index, match in enumerate(matches):
        key = match.group(1)
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(value)
        extension[key] = value[start:end].strip()
    return extension


def _parse_cef_line(line: str) -> NormalizedEvent:
    if not line.startswith("CEF:"):
        raise ParseError("malformed_cef", "CEF message must start with 'CEF:'")
    parts = _split_unescaped(line, "|", maxsplit=7)
    if len(parts) < 7:
        raise ParseError("malformed_cef", "CEF message must contain 7 header fields")
    version = _unescape(parts[0]).split(":", 1)[1] if ":" in parts[0] else "0"
    vendor = sanitize_text(_unescape(parts[1]), max_length=120)
    product_name = sanitize_text(_unescape(parts[2]), max_length=120)
    header_version = sanitize_text(_unescape(parts[3]), max_length=40)
    signature_id = sanitize_text(_unescape(parts[4]), max_length=120)
    name = sanitize_text(_unescape(parts[5]), max_length=300)
    severity_raw = sanitize_text(_unescape(parts[6]), max_length=40)
    extension_raw = parts[7] if len(parts) > 7 else ""
    extension = _parse_extension(extension_raw)

    lower_extension = {key.lower(): key for key in extension}
    consumed: set[str] = set()
    values: dict[str, Any] = {}

    def take(*keys: str) -> Any:
        for key in keys:
            original = lower_extension.get(key)
            if original is not None:
                consumed.add(original)
                return _unescape(extension[original])
        return None

    for field, canonical in CEF_EXTENSION_MAP.items():
        if canonical == "host_name" and "host_name" in values:
            continue
        raw_value = take(field)
        if raw_value is None:
            continue
        if canonical in values and canonical != "host_name":
            continue
        values[canonical] = raw_value

    custom: dict[str, Any] = {}
    for key, raw_value in extension.items():
        if key in consumed:
            continue
        if _CUSTOM_KEY_RE.match(key):
            custom[key] = _unescape(raw_value)
            consumed.add(key)
    reason = values.get("reason")
    request_method = values.get("request_method")
    file_name = values.get("file_name")
    external_id = values.get("external_id")
    action = values.get("action")
    category = values.get("category")
    bytes_in = values.get("bytes_in")
    bytes_out = values.get("bytes_out")
    status_value = values.get("status")
    url = values.get("url")

    occurred_at = None
    for key in ("rt", "start", "end", "devicereceipttime"):
        original = lower_extension.get(key)
        if original:
            occurred_at = _unescape(extension[original])
            break

    unmapped = {key: _unescape(value) for key, value in extension.items() if key not in consumed}
    message = values.get("message") or name or f"{vendor} {product_name}".strip() or "CEF event"
    extra: dict[str, Any] = {
        "action": action,
        "outcome": status_value,
        "category": category,
        "bytes_in": bytes_in,
        "bytes_out": bytes_out,
        "external_id": external_id,
        "file_name": file_name,
        "request_method": request_method,
        "reason": reason,
        "signature_id": signature_id,
        "cef_version": version,
        "header_version": header_version,
        "custom": custom or None,
        "host": values.get("host_name"),
    }
    return make_event(
        raw_format="cef",
        raw={
            "format": "cef",
            "line": line,
            "header": {
                "version": version,
                "vendor": vendor,
                "product": product_name,
                "header_version": header_version,
                "signature_id": signature_id,
                "name": name,
                "severity": severity_raw,
            },
            "extension": extension,
        },
        message=message,
        occurred_at=occurred_at,
        severity=severity_from_cef(severity_raw),
        status=status_value,
        src_ip=values.get("src_ip"),
        dst_ip=values.get("dst_ip"),
        src_port=values.get("src_port"),
        dst_port=values.get("dst_port"),
        protocol=values.get("protocol"),
        user_name=values.get("user_name"),
        host_name=values.get("host_name"),
        process_name=values.get("process_name"),
        file_hash_sha256=values.get("file_hash_sha256"),
        url=url,
        domain=_domain_from_url(str(url)) if url else None,
        extra={key: value for key, value in extra.items() if value not in (None, "")},
        unmapped=unmapped,
        product=f"{vendor} {product_name}".strip() or "CEF",
    )


# ---------------------------------------------------------------------------
# LEEF
# ---------------------------------------------------------------------------

LEEF_FIELD_MAP: dict[str, str] = {
    "src": "src_ip",
    "srcip": "src_ip",
    "dst": "dst_ip",
    "dstip": "dst_ip",
    "spt": "src_port",
    "srcport": "src_port",
    "dpt": "dst_port",
    "dstport": "dst_port",
    "proto": "protocol",
    "usrname": "user_name",
    "username": "user_name",
    "user": "user_name",
    "identuser": "user_name",
    "srchost": "host_name",
    "srchostname": "host_name",
    "dsthost": "host_name",
    "dsthostname": "host_name",
    "hostname": "host_name",
    "host": "host_name",
    "proc": "process_name",
    "process": "process_name",
    "sev": "severity",
    "cat": "category",
    "msg": "message",
    "action": "action",
    "devtime": "occurred_at",
    "url": "url",
    "domain": "domain",
    "fqdn": "domain",
    "filehash": "file_hash_sha256",
    "sha256": "file_hash_sha256",
    "bytesout": "bytes_out",
    "out": "bytes_out",
    "bytesin": "bytes_in",
    "in": "bytes_in",
    "eventid": "external_id",
    "eventname": "message",
}


def _parse_leef_line(line: str) -> NormalizedEvent:
    if not line.startswith("LEEF:"):
        raise ParseError("malformed_leef", "LEEF message must start with 'LEEF:'")
    parts = line.split("|", 5)
    if len(parts) < 6:
        raise ParseError("malformed_leef", "LEEF message must contain header and attributes")
    version = sanitize_text(parts[0].split(":", 1)[1], max_length=20)
    vendor = sanitize_text(parts[1], max_length=120)
    product_name = sanitize_text(parts[2], max_length=120)
    header_version = sanitize_text(parts[3], max_length=40)
    event_id = sanitize_text(parts[4], max_length=120)
    remainder = parts[5]
    delimiter = "\t"
    if version.startswith("2") and remainder:
        if remainder[0] in {"^", "|", ",", "\t"}:
            delimiter = remainder[0]
            remainder = remainder[1:]
        elif remainder.startswith("\\u0009"):
            delimiter = "\t"
            remainder = remainder[len("\\u0009") :]
    attributes: dict[str, str] = {}
    for token in _split_unescaped(remainder, delimiter):
        if not token:
            continue
        key, separator, raw_value = token.partition("=")
        if not separator:
            continue
        attributes[key.strip()] = _unescape(raw_value.strip())

    lower_attributes = {key.lower(): key for key in attributes}
    consumed: set[str] = set()
    values: dict[str, Any] = {}
    for field, canonical in LEEF_FIELD_MAP.items():
        original = lower_attributes.get(field)
        if original is None:
            continue
        consumed.add(original)
        value = _unescape(attributes[original])
        if canonical == "host_name" and values.get("host_name"):
            continue
        if canonical == "message" and values.get("message"):
            continue
        values.setdefault(canonical, value)

    severity_raw = values.get("severity")
    severity = severity_from_cef(severity_raw) if severity_raw is not None else 0
    message = values.get("message") or event_id or "LEEF event"
    unmapped = {key: _unescape(value) for key, value in attributes.items() if key not in consumed}
    extra: dict[str, Any] = {
        "action": values.get("action"),
        "category": values.get("category"),
        "bytes_in": values.get("bytes_in"),
        "bytes_out": values.get("bytes_out"),
        "external_id": values.get("external_id") or event_id,
        "leef_version": version,
        "header_version": header_version,
        "event_id": event_id,
    }
    url = values.get("url")
    return make_event(
        raw_format="leef",
        raw={
            "format": "leef",
            "line": line,
            "header": {
                "version": version,
                "vendor": vendor,
                "product": product_name,
                "header_version": header_version,
                "event_id": event_id,
            },
            "attributes": attributes,
        },
        message=message,
        occurred_at=values.get("occurred_at"),
        severity=severity,
        src_ip=values.get("src_ip"),
        dst_ip=values.get("dst_ip"),
        src_port=values.get("src_port"),
        dst_port=values.get("dst_port"),
        protocol=values.get("protocol"),
        user_name=values.get("user_name"),
        host_name=values.get("host_name"),
        process_name=values.get("process_name"),
        file_hash_sha256=values.get("file_hash_sha256"),
        url=url,
        domain=values.get("domain") or (_domain_from_url(str(url)) if url else None),
        extra={key: value for key, value in extra.items() if value not in (None, "")},
        unmapped=unmapped,
        product=f"{vendor} {product_name}".strip() or "LEEF",
    )


# ---------------------------------------------------------------------------
# Syslog
# ---------------------------------------------------------------------------

_SYSLOG_PRI_RE = re.compile(r"^<(\d{1,3})>(.*)$", re.DOTALL)
_RFC5424_RE = re.compile(
    r"^(?P<version>\d{1,2}) (?P<timestamp>\S+) (?P<host>\S+) (?P<app>\S+) (?P<procid>\S+) "
    r"(?P<msgid>\S+) (?P<tail>.*)$",
    re.DOTALL,
)
_RFC3164_TIME_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})\s+(?P<rest>.*)$",
    re.DOTALL,
)
_SYSLOG_TAG_RE = re.compile(r"^(?P<tag>[A-Za-z0-9_.\-/]+?)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$", re.DOTALL)
_SD_PARAM_RE = re.compile(r'([A-Za-z0-9_.@-]+)="((?:[^"\\]|\\.)*)"')


def _parse_structured_data(text: str) -> tuple[list[dict[str, Any]], int]:
    elements: list[dict[str, Any]] = []
    index = 0
    while index < len(text) and text[index] == "[":
        cursor = index + 1
        in_quotes = False
        escaped = False
        while cursor < len(text):
            char = text[cursor]
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_quotes = not in_quotes
            elif char == "]" and not in_quotes:
                break
            cursor += 1
        if cursor >= len(text):
            raise ParseError("malformed_syslog", "Unterminated syslog structured data")
        element = text[index + 1 : cursor]
        identifier, _, params = element.partition(" ")
        parameters = {match.group(1): _unescape(match.group(2)) for match in _SD_PARAM_RE.finditer(params)}
        elements.append({"id": identifier, "parameters": parameters})
        index = cursor + 1
    if not elements:
        raise ParseError("malformed_syslog", "Invalid syslog structured data")
    return elements, index


def _syslog_time(value: str, now: datetime) -> datetime:
    if value in {"-", ""}:
        return now
    return parse_timestamp(value, default=now)


def _parse_syslog_line(line: str, *, now: datetime | None = None) -> NormalizedEvent:
    now = now or datetime.now(UTC)
    match = _SYSLOG_PRI_RE.match(line.lstrip("\ufeff"))
    if match is None:
        raise ParseError("malformed_syslog", "Syslog message must start with a priority value")
    priority = int(match.group(1))
    if priority < 0 or priority > 191:
        raise ParseError("malformed_syslog", "Syslog priority must be between 0 and 191")
    facility = priority // 8
    syslog_severity = priority % 8
    remainder = match.group(2)
    if not remainder.strip():
        raise ParseError("malformed_syslog", "Syslog message has no content after the priority")
    structured_data: list[dict[str, Any]] | None = None
    extra: dict[str, Any] = {
        "facility": facility,
        "priority": priority,
        "syslog_severity": syslog_severity,
        "log_source": "syslog",
    }

    rfc5424 = _RFC5424_RE.match(remainder)
    if rfc5424 is not None:
        version = rfc5424.group("version")
        timestamp = _syslog_time(rfc5424.group("timestamp"), now)
        host_name = None if rfc5424.group("host") in {"-", ""} else rfc5424.group("host")
        app_name = None if rfc5424.group("app") in {"-", ""} else rfc5424.group("app")
        procid = None if rfc5424.group("procid") in {"-", ""} else rfc5424.group("procid")
        msgid = None if rfc5424.group("msgid") in {"-", ""} else rfc5424.group("msgid")
        tail = rfc5424.group("tail")
        if tail.startswith("-"):
            message = tail[1:].lstrip(" ")
        elif tail.startswith("["):
            structured_data, consumed = _parse_structured_data(tail)
            message = tail[consumed:].lstrip(" ")
        else:
            raise ParseError("malformed_syslog", "RFC 5424 structured data must start with '[' or '-'")
        extra.update(
            {
                "rfc": "5424",
                "version": version,
                "procid": procid,
                "msgid": msgid,
                "app_name": app_name,
            }
        )
        if structured_data:
            extra["structured_data"] = structured_data
        user_name = None
        for element in structured_data or []:
            parameters = element.get("parameters", {})
            for key in ("user", "suser", "username", "usrName", "uid", "targetUserName"):
                if parameters.get(key):
                    user_name = parameters[key]
                    break
            if user_name:
                break
        if message.startswith(("CEF:", "LEEF:")):
            return _syslog_embedded(line, message, timestamp, host_name, user_name, extra, structured_data)
        return make_event(
            raw_format="syslog",
            raw={"format": "syslog", "line": line, "rfc": "5424", "structured_data": structured_data},
            message=message or line,
            occurred_at=timestamp,
            severity=severity_from_syslog(syslog_severity),
            host_name=host_name,
            process_name=app_name,
            user_name=user_name,
            extra=extra,
            product=app_name or "syslog",
        )

    timestamp = now
    rest = remainder
    time_match = _RFC3164_TIME_RE.match(rest)
    if time_match is not None:
        month = _MONTHS.get(time_match.group("month").lower(), 0)
        if not month:
            raise ParseError("malformed_syslog", "Unknown syslog month")
        year = now.year
        try:
            timestamp = datetime(
                year,
                month,
                int(time_match.group("day")),
                int(time_match.group("hour")),
                int(time_match.group("minute")),
                int(time_match.group("second")),
                tzinfo=UTC,
            )
        except ValueError as exc:
            raise ParseError("malformed_syslog", "Invalid RFC 3164 timestamp") from exc
        if timestamp > now.replace(microsecond=0) + timedelta(days=1):
            timestamp = timestamp.replace(year=year - 1)
        rest = time_match.group("rest")

    host_name = None
    if rest:
        host_name, _, rest = rest.partition(" ")
        host_name = host_name if host_name not in {"-", ""} else None

    if rest.startswith(("CEF:", "LEEF:")):
        return _syslog_embedded(line, rest, timestamp, host_name, None, extra, structured_data)

    tag_match = _SYSLOG_TAG_RE.match(rest)
    process_name = None
    if tag_match is not None:
        process_name = tag_match.group("tag") or None
        message = tag_match.group("msg")
        if tag_match.group("pid"):
            extra["pid"] = int(tag_match.group("pid"))
    else:
        message = rest
    extra.update({"rfc": "3164", "app_name": process_name})
    if message.startswith(("CEF:", "LEEF:")):
        return _syslog_embedded(line, message, timestamp, host_name, None, extra, structured_data)
    return make_event(
        raw_format="syslog",
        raw={"format": "syslog", "line": line, "rfc": "3164"},
        message=message or line,
        occurred_at=timestamp,
        severity=severity_from_syslog(syslog_severity),
        host_name=host_name,
        process_name=process_name,
        extra=extra,
        product=process_name or "syslog",
    )


def _syslog_embedded(
    line: str,
    message: str,
    timestamp: datetime,
    host_name: str | None,
    user_name: str | None,
    extra: dict[str, Any],
    structured_data: list[dict[str, Any]] | None,
) -> NormalizedEvent:
    """Parse CEF/LEEF carried inside a syslog MSG, keeping syslog context."""
    embedded = _parse_cef_line(message) if message.startswith("CEF:") else _parse_leef_line(message)
    merged_extra = dict(embedded.extra)
    merged_extra["syslog"] = sanitize_text(line, max_length=4000)
    merged_extra.update(extra)
    return make_event(
        raw_format="syslog",
        raw={
            "format": "syslog",
            "line": line,
            "embedded_format": embedded.raw_format,
            "embedded": embedded.raw,
            "structured_data": structured_data,
        },
        message=embedded.message,
        occurred_at=timestamp,
        severity=embedded.severity_id,
        status_id=embedded.status_id,
        class_uid=embedded.class_uid,
        class_name=embedded.class_name,
        category_uid=embedded.category_uid,
        activity_id=embedded.activity_id,
        src_ip=embedded.src_ip,
        dst_ip=embedded.dst_ip,
        src_port=embedded.src_port,
        dst_port=embedded.dst_port,
        protocol=embedded.protocol,
        user_name=embedded.user_name or user_name,
        host_name=embedded.host_name or host_name,
        process_name=embedded.process_name,
        file_hash_sha256=embedded.file_hash_sha256,
        url=embedded.url,
        domain=embedded.domain,
        extra=merged_extra,
        unmapped=embedded.normalized.get("unmapped", {}),
        product=embedded.normalized.get("metadata", {}).get("product") or "syslog",
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

_CONTENT_TYPE_FORMATS = {
    "application/json": "json",
    "application/x-ndjson": "json",
    "application/ld+json": "json",
    "text/json": "json",
    "application/cef": "cef",
    "text/cef": "cef",
    "application/leef": "leef",
    "text/leef": "leef",
    "text/plain": "syslog",
    "application/syslog": "syslog",
    "application/x-syslog": "syslog",
    "text/x-syslog": "syslog",
    "application/x-otel": "otel",
}

_SUPPORTED_PARSERS = {"auto", "json", "cef", "leef", "syslog", "otel"}


def _decode(body: bytes) -> str:
    if not body or not body.strip():
        raise ParseError("empty_payload", "Payload is empty")
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ParseError("invalid_encoding", "Payload is not valid UTF-8") from exc
    return text.lstrip("\ufeff")


def _sniff(text: str) -> str | None:
    stripped = text.lstrip(" \t\r\n")
    if stripped.startswith(("{", "[")):
        return "json"
    if stripped.startswith("CEF:"):
        return "cef"
    if stripped.startswith("LEEF:"):
        return "leef"
    if re.match(r"^<\d{1,3}>", stripped):
        return "syslog"
    return None


def _select_format(*, parser: str, content_type: str | None, text: str) -> str:
    if parser not in _SUPPORTED_PARSERS:
        raise ParseError("unsupported_parser", f"Unsupported parser: {parser}")
    if parser != "auto":
        return parser
    hint = None
    if content_type:
        mime = content_type.split(";", 1)[0].strip().lower()
        hint = _CONTENT_TYPE_FORMATS.get(mime)
    sniffed = _sniff(text)
    if sniffed:
        return sniffed
    if hint:
        return hint
    # Unstructured single-line logs are almost always syslog in this pipeline.
    return "syslog"


def parse_payload(
    body: bytes,
    *,
    content_type: str | None = None,
    parser: str = "auto",
    now: datetime | None = None,
) -> list[NormalizedEvent]:
    """Parse a request body into normalized events or raise :class:`ParseError`."""
    text = _decode(body)
    raw_format = _select_format(parser=parser, content_type=content_type, text=text)

    if raw_format in {"json", "otel"}:
        try:
            document = _loads_json(text)
        except ValueError:
            # Tolerate NDJSON when every line is a complete JSON document.
            lines = [line for line in text.splitlines() if line.strip()]
            if len(lines) > 1:
                try:
                    decoded = [_loads_json(line) for line in lines]
                except ValueError as exc:
                    raise ParseError("malformed_json", "Payload is not valid JSON") from exc
                events: list[NormalizedEvent] = []
                for item in decoded:
                    events.extend(_parse_otel_document(item) if raw_format == "otel" else _parse_json_document(item))
                if len(events) > MAX_EVENTS_PER_PAYLOAD:
                    raise ParseError(
                        "too_many_events", f"A payload may contain at most {MAX_EVENTS_PER_PAYLOAD} events"
                    ) from None
                return events
            raise ParseError("malformed_json", "Payload is not valid JSON") from None
        events = _parse_otel_document(document) if raw_format == "otel" else _parse_json_document(document)
        if len(events) > MAX_EVENTS_PER_PAYLOAD:
            raise ParseError("too_many_events", f"A payload may contain at most {MAX_EVENTS_PER_PAYLOAD} events")
        return events

    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        raise ParseError("empty_payload", "Payload contains no log lines")
    if len(lines) > MAX_EVENTS_PER_PAYLOAD:
        raise ParseError("too_many_events", f"A payload may contain at most {MAX_EVENTS_PER_PAYLOAD} events")

    now = now or datetime.now(UTC)
    events = []
    for line in lines:
        if raw_format == "cef":
            events.append(_parse_cef_line(line))
        elif raw_format == "leef":
            events.append(_parse_leef_line(line))
        else:
            events.append(_parse_syslog_line(line, now=now))
    return events


__all__ = [
    "MAX_EVENTS_PER_PAYLOAD",
    "ParseError",
    "parse_payload",
]
