"""LISTEN/NOTIFY wake-up for the outbox (polling remains the fallback)."""

from __future__ import annotations

import threading

import psycopg

from app.services import outbox
from app.workers.outbox_listener import CHANNEL, OutboxListener, postgres_dsn


def test_committed_enqueue_emits_a_notification(seeded, db) -> None:
    org = seeded["org"]
    with psycopg.connect(postgres_dsn(), autocommit=True) as connection:
        connection.execute(f"LISTEN {CHANNEL}")
        event_id = outbox.enqueue(
            db,
            org_id=org.id,
            event_type="alert.created",
            aggregate_type="alert",
            aggregate_id="notify-1",
            payload={"title": "notify"},
        )
        assert event_id is not None
        # Nothing is delivered before the business transaction commits.
        assert list(connection.notifies(timeout=0.2, stop_after=1)) == []
        db.commit()
        notifications = list(connection.notifies(timeout=5.0, stop_after=1))
    assert notifications, "expected an outbox notification after commit"
    assert notifications[0].channel == CHANNEL
    assert notifications[0].payload == str(event_id)


def test_listener_thread_wakes_the_dispatcher_on_commit(seeded, db) -> None:
    wake = threading.Event()
    stop = threading.Event()
    listener = OutboxListener(wake=wake, stop=stop).start()
    try:
        assert listener.ready.wait(5.0), "listener did not become ready"
        org = seeded["org"]
        outbox.enqueue(
            db,
            org_id=org.id,
            event_type="incident.created",
            aggregate_type="incident",
            aggregate_id="notify-2",
            payload={"title": "notify"},
        )
        db.commit()
        assert wake.wait(5.0), "listener did not wake the dispatcher"
    finally:
        stop.set()
        listener.join(timeout=5.0)
    assert not listener.stats()["alive"]
