"""Transactional outbox: atomicity, leases, retries, DLQ and real consumers."""

from __future__ import annotations

import uuid
from datetime import timedelta

from sqlalchemy import select

from app.core.db import utcnow
from app.models.core import Notification, Organization
from app.models.events import Alert, DetectionRule, SecurityEvent
from app.models.incidents import Incident
from app.models.operations import (
    OUTBOX_DEAD_LETTER,
    OUTBOX_PENDING,
    OUTBOX_PROCESSED,
    OUTBOX_PROCESSING,
    OutboxEvent,
)
from app.modules.incidents.service import create_incident_core
from app.services import outbox
from app.services.detection import run_detection


def _event(org_id, **overrides):
    values = {
        "org_id": org_id,
        "event_uid": str(uuid.uuid4()),
        "occurred_at": utcnow(),
        "class_uid": 6003,
        "class_name": "API Activity",
        "category_uid": 6,
        "severity_id": 3,
        "message": "generic event",
        "raw": {},
        "normalized": {"extra": {}},
        "raw_format": "json",
        "schema_version": "1.1.0",
        "ioc_matches": [],
        "mitre_techniques": [],
        "is_demo": False,
    }
    values.update(overrides)
    return SecurityEvent(**values)


def _rule(org_id):
    return DetectionRule(
        org_id=org_id,
        name="outbox-rule",
        severity="high",
        status="production",
        enabled=True,
        version=1,
        logsource={},
        definition={"selection": {"message": {"contains": "outbox"}}, "condition": "and"},
        mitre=["T1110"],
        tags=["test"],
        created_by="tests",
    )


def test_enqueue_rolls_back_with_the_domain_transaction(seeded, db) -> None:
    org = seeded["org"]
    event_id = outbox.enqueue(
        db,
        org_id=org.id,
        event_type="alert.created",
        aggregate_type="alert",
        aggregate_id="x",
        payload={"title": "rollback"},
    )
    assert event_id is not None
    db.rollback()
    assert db.execute(select(OutboxEvent)).first() is None


def test_dedupe_key_makes_enqueue_idempotent(seeded, db) -> None:
    org = seeded["org"]
    first = outbox.enqueue(
        db,
        org_id=org.id,
        event_type="alert.created",
        aggregate_type="alert",
        aggregate_id="1",
        dedupe_key="same-key",
    )
    second = outbox.enqueue(
        db,
        org_id=org.id,
        event_type="alert.created",
        aggregate_type="alert",
        aggregate_id="2",
        dedupe_key="same-key",
    )
    db.commit()
    assert first is not None
    assert second is None
    assert len(list(db.execute(select(OutboxEvent)).scalars())) == 1


def test_dispatch_creates_one_notification_and_marks_event_processed(seeded, db) -> None:
    org = seeded["org"]
    outbox.enqueue(
        db,
        org_id=org.id,
        event_type="alert.created",
        aggregate_type="alert",
        aggregate_id="alert-1",
        payload={"title": "Suspicious login", "severity": "high"},
    )
    db.commit()

    result = outbox.dispatch_once(db, limit=10)
    assert result == {"claimed": 1, "processed": 1, "retried": 0, "dead_lettered": 0}
    event = db.execute(select(OutboxEvent)).scalar_one()
    assert event.status == OUTBOX_PROCESSED
    assert event.processed_at is not None
    notifications = list(db.execute(select(Notification)).scalars())
    assert len(notifications) == 1
    assert notifications[0].title == "Suspicious login"
    assert notifications[0].resource_id == "alert-1"

    # A duplicate delivery (worker crashed after commit, before ack) does not
    # create a second user-facing notification.
    event.status = OUTBOX_PROCESSING
    db.commit()
    outbox._handle_notification(db, event)
    db.commit()
    assert len(list(db.execute(select(Notification)).scalars())) == 1


def test_transient_failure_is_retried_with_backoff(seeded, db, monkeypatch) -> None:
    org = seeded["org"]
    calls = {"n": 0}

    def flaky(db_session, event):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("temporary upstream error")
        outbox._handle_notification(db_session, event)

    monkeypatch.setitem(outbox.HANDLERS, "incident.created", flaky)
    outbox.enqueue(db, org_id=org.id, event_type="incident.created", aggregate_type="incident", aggregate_id="i-1")
    db.commit()

    first = outbox.dispatch_once(db, limit=10)
    assert first["retried"] == 1
    row = db.execute(select(OutboxEvent)).scalar_one()
    assert row.status == OUTBOX_PENDING
    assert row.attempts == 1
    assert row.available_at > utcnow()
    assert "temporary upstream error" in (row.last_error or "")

    second = outbox.dispatch_once(db, limit=10, now=utcnow() + timedelta(minutes=10))
    assert second["processed"] == 1
    row = db.execute(select(OutboxEvent)).scalar_one()
    assert row.status == OUTBOX_PROCESSED
    assert row.attempts == 2


def test_poison_event_moves_to_dead_letter_after_max_attempts(seeded, db, monkeypatch) -> None:
    org = seeded["org"]

    def always_fails(db_session, event):
        raise RuntimeError("poison")

    monkeypatch.setitem(outbox.HANDLERS, "alert.created", always_fails)
    outbox.enqueue(db, org_id=org.id, event_type="alert.created", aggregate_type="alert", aggregate_id="a")
    db.commit()
    row = db.execute(select(OutboxEvent)).scalar_one()
    row.max_attempts = 2
    db.commit()

    outbox.dispatch_once(db, limit=10)
    db.expire_all()
    row = db.execute(select(OutboxEvent)).scalar_one()
    assert row.status == OUTBOX_PENDING
    outbox.dispatch_once(db, limit=10, now=utcnow() + timedelta(hours=2))
    db.expire_all()
    row = db.execute(select(OutboxEvent)).scalar_one()
    assert row.status == OUTBOX_DEAD_LETTER
    assert row.last_error and "poison" in row.last_error


def test_unknown_event_type_is_dead_lettered_not_retried(seeded, db) -> None:
    org = seeded["org"]
    outbox.enqueue(db, org_id=org.id, event_type="never.registered", aggregate_type="test")
    db.commit()
    result = outbox.dispatch_once(db, limit=10)
    assert result["dead_lettered"] == 1
    row = db.execute(select(OutboxEvent)).scalar_one()
    assert row.status == OUTBOX_DEAD_LETTER
    assert "unregistered" in row.last_error.lower() or "never.registered" in row.last_error


def test_expired_lease_is_reclaimed(seeded, db) -> None:
    org = seeded["org"]
    outbox.enqueue(db, org_id=org.id, event_type="alert.created", aggregate_type="alert", aggregate_id="lease")
    db.commit()
    row = db.execute(select(OutboxEvent)).scalar_one()
    row.status = OUTBOX_PROCESSING
    row.locked_until = utcnow() - timedelta(seconds=5)
    row.attempts = 1
    db.commit()

    result = outbox.dispatch_once(db, limit=10)
    assert result["processed"] == 1
    row = db.execute(select(OutboxEvent)).scalar_one()
    assert row.status == OUTBOX_PROCESSED


def test_detection_alert_and_incident_emit_outbox_events(seeded, db) -> None:
    org = seeded["org"]
    db.add(_rule(org.id))
    event = _event(org.id, message="outbox alert")
    db.add(event)
    db.commit()
    outcome = run_detection(db, org_id=org.id, events=[event])
    db.commit()
    assert outcome.alerts_created == 1
    alert = db.execute(select(Alert).where(Alert.org_id == org.id)).scalar_one()
    queued = db.execute(select(OutboxEvent).where(OutboxEvent.event_type == "alert.created")).scalar_one()
    assert queued.aggregate_id == str(alert.id)

    incident = create_incident_core(db, org, title="Outbox incident", severity="high", actor="tests")
    db.commit()
    incident_event = db.execute(select(OutboxEvent).where(OutboxEvent.event_type == "incident.created")).scalar_one()
    assert incident_event.aggregate_id == str(incident.id)
    assert isinstance(incident, Incident)

    outbox.dispatch_once(db, limit=10)
    notifications = list(db.execute(select(Notification)).scalars())
    assert {item.resource_type for item in notifications} == {"alert", "incident"}


def test_notifications_are_tenant_scoped(seeded, db) -> None:
    org = seeded["org"]
    other = Organization(slug="other-outbox", name="Other", kind="private", country="ES")
    db.add(other)
    db.commit()
    outbox.enqueue(db, org_id=org.id, event_type="alert.created", aggregate_type="alert", aggregate_id="a")
    outbox.enqueue(db, org_id=other.id, event_type="alert.created", aggregate_type="alert", aggregate_id="b")
    db.commit()
    outbox.dispatch_once(db, limit=10)
    mine = list(db.execute(select(Notification).where(Notification.org_id == org.id)).scalars())
    theirs = list(db.execute(select(Notification).where(Notification.org_id == other.id)).scalars())
    assert len(mine) == 1 and len(theirs) == 1
