"""Worker runtime: scheduling decisions and safe single-pass execution."""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy.orm import Session

from app.core.db import utcnow
from app.models.connectors import Connector
from app.workers import runtime


def _connector(db: Session, org_id, name: str, *, minutes_ago: int | None, enabled: bool = True) -> Connector:
    connector = Connector(
        org_id=org_id,
        name=name,
        connector_type="generic_webhook",
        base_url="https://example.eu/hook",
        auth_type="none",
        status="healthy",
        enabled=enabled,
        config={"sync_interval_minutes": 15},
        last_success_at=None if minutes_ago is None else utcnow() - timedelta(minutes=minutes_ago),
    )
    db.add(connector)
    db.flush()
    return connector


def test_due_connectors_respects_interval_and_enabled_flag(seeded, db: Session) -> None:
    fresh = _connector(db, seeded["org"].id, "fresh", minutes_ago=1)
    stale = _connector(db, seeded["org"].id, "stale", minutes_ago=120)
    never = _connector(db, seeded["org"].id, "never", minutes_ago=None)
    disabled = _connector(db, seeded["org"].id, "disabled", minutes_ago=None, enabled=False)
    db.commit()

    due = runtime.due_connectors(db)
    ids = {connector.id for connector in due}
    assert stale.id in ids
    assert never.id in ids
    assert fresh.id not in ids
    assert disabled.id not in ids


def test_worker_single_pass_is_safe_on_empty_queue(seeded, db: Session) -> None:
    result = runtime.run_playbooks_once(db)
    assert result["claimed"] == 0
    assert result["processed"] == 0

    sync_result = runtime.sync_connectors_once(db)
    assert sync_result == {"synced": 0, "failed": 0}
