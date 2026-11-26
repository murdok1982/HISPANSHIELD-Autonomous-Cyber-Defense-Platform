"""Log normalization to OCSF 1.1 (parsers, mapping primitives, severity model)."""

from app.services.normalization.ocsf import (
    OCSF_CLASSES,
    SCHEMA_VERSION,
    NormalizedEvent,
    identify_ip,
    make_event,
    parse_timestamp,
    sanitize_text,
    sanitize_value,
    severity_from_cef,
    severity_from_otel,
    severity_from_syslog,
    severity_to_id,
    status_from_value,
)
from app.services.normalization.parsers import MAX_EVENTS_PER_PAYLOAD, ParseError, parse_payload

__all__ = [
    "MAX_EVENTS_PER_PAYLOAD",
    "OCSF_CLASSES",
    "SCHEMA_VERSION",
    "NormalizedEvent",
    "ParseError",
    "identify_ip",
    "make_event",
    "parse_payload",
    "parse_timestamp",
    "sanitize_text",
    "sanitize_value",
    "severity_from_cef",
    "severity_from_otel",
    "severity_from_syslog",
    "severity_to_id",
    "status_from_value",
]
