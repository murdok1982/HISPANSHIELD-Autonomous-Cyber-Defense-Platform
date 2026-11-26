"""SSE firehose: cursor semantics, tenant isolation and wire format."""

from __future__ import annotations

import uuid

from app.core.db import SessionLocal, utcnow
from app.main import create_app
from app.models.core import Organization
from app.models.events import SecurityEvent
from app.modules.events.stream import (
    current_head,
    fetch_after,
    format_sse,
    iter_events,
    parse_last_event_id,
    serialize_event,
)


def _event(org_id, message: str) -> SecurityEvent:
    return SecurityEvent(
        org_id=org_id,
        event_uid=str(uuid.uuid4()),
        occurred_at=utcnow(),
        class_uid=6003,
        class_name="Network Activity",
        category_uid=4,
        severity_id=3,
        message=message,
        raw={"message": message},
        normalized={},
        raw_format="json",
        schema_version="1.1.0",
        ioc_matches=[],
        mitre_techniques=["T1071"],
        is_demo=False,
    )


def test_cursor_resumes_after_last_delivered_id(seeded, db) -> None:
    org = seeded["org"]
    db.add_all([_event(org.id, "first"), _event(org.id, "second"), _event(org.id, "third")])
    db.commit()
    with SessionLocal() as session:
        head = current_head(session, org.id)
        rows = fetch_after(session, org.id, 0)
        assert [row.message for row in rows] == ["first", "second", "third"]
        assert fetch_after(session, org.id, rows[0].id)[0].message == "second"
        assert head == rows[-1].id


def test_iter_events_is_tenant_scoped(seeded, db) -> None:
    org = seeded["org"]
    other = Organization(slug="sse-other", name="SSE Other", kind="private", country="ES")
    db.add(other)
    db.commit()
    foreign = _event(other.id, "foreign secret")
    mine = _event(org.id, "mine")
    db.add_all([foreign, mine])
    db.commit()

    delivered = list(iter_events(org.id, cursor=0, poll_seconds=0, max_events=1))
    assert len(delivered) == 1
    event_id, payload = delivered[0]
    assert event_id == mine.id
    assert payload["message"] == "mine"
    assert "foreign" not in payload["message"]


def test_serialize_and_sse_format_are_stable(seeded, db) -> None:
    org = seeded["org"]
    event = _event(org.id, "line\nwith newline")
    db.add(event)
    db.commit()
    payload = serialize_event(event)
    frame = format_sse(event.id, payload)
    assert frame.startswith(f"id: {event.id}\nevent: security_event\ndata: ")
    assert frame.endswith("\n\n")
    assert "\n" not in frame.split("data: ", 1)[1][:-2]
    assert payload["mitre_techniques"] == ["T1071"]


def test_last_event_id_parser_never_accepts_garbage() -> None:
    assert parse_last_event_id("42") == 42
    assert parse_last_event_id(" 7 ") == 7
    assert parse_last_event_id("0") == 0
    assert parse_last_event_id("-1") is None
    assert parse_last_event_id("abc") is None
    assert parse_last_event_id(None) is None


def test_stream_route_is_registered() -> None:
    schema = create_app().openapi()
    assert "/api/v1/events/stream" in schema["paths"]
    operation = schema["paths"]["/api/v1/events/stream"]["get"]
    assert operation["summary"].startswith("Server-Sent Events")
