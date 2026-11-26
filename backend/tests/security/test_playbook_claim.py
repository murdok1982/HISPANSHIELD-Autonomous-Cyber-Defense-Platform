"""Concurrency and crash-recovery guarantees for the durable playbook worker."""

from __future__ import annotations

import threading
from datetime import timedelta

from sqlalchemy import func, select

from app.core.db import SessionLocal, utcnow
from app.models.core import Organization
from app.models.incidents import Playbook, PlaybookExecution
from app.services import playbook_engine
from app.services.broker import BrokerActor
from app.services.playbook_engine import create_execution, worker_run_once

WORKER_COUNT = 4
EXECUTIONS = 12
CLAIM_LIMIT = 4


def _playbook(db, org: Organization) -> Playbook:
    playbook = Playbook(
        org_id=org.id,
        name="Worker concurrency playbook",
        version=1,
        status="published",
        trigger={},
        definition={
            "steps": [
                {"key": "investigate", "name": "Investigate", "action": "internal.investigate", "params": {}},
            ]
        },
        min_autonomy_level="A1",
    )
    db.add(playbook)
    db.commit()
    db.refresh(playbook)
    return playbook


def _execution(db, org: Organization, playbook: Playbook) -> PlaybookExecution:
    return create_execution(
        db,
        org=org,
        playbook=playbook,
        actor=BrokerActor(id="test-operator", email="operator@hispanshield.eu"),
        trigger="manual",
        context={},
    )


def test_four_workers_claim_each_execution_exactly_once(seeded, db) -> None:
    org = db.get(Organization, seeded["org"].id)
    playbook = _playbook(db, org)
    executions = [_execution(db, org, playbook) for _ in range(EXECUTIONS)]
    expected_ids = {str(execution.id) for execution in executions}

    barrier = threading.Barrier(WORKER_COUNT)
    results: list[dict] = []
    errors: list[BaseException] = []
    result_lock = threading.Lock()

    def run_worker() -> None:
        session = SessionLocal()
        try:
            barrier.wait(timeout=10)
            result = worker_run_once(session, limit=CLAIM_LIMIT)
            with result_lock:
                results.append(result)
        except BaseException as exc:  # noqa: BLE001 - surfaced through ``errors``
            with result_lock:
                errors.append(exc)
        finally:
            session.close()

    threads = [threading.Thread(target=run_worker, daemon=True) for _ in range(WORKER_COUNT)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
        assert not thread.is_alive(), "worker thread deadlocked"

    assert errors == []
    claimed = [execution_id for result in results for execution_id in result["claimed_ids"]]
    # Each execution is claimed by exactly one worker: no duplicate ownership.
    assert len(claimed) == len(set(claimed)) == EXECUTIONS
    assert set(claimed) == expected_ids

    db.expire_all()
    rows = list(
        db.execute(select(PlaybookExecution).where(PlaybookExecution.id.in_([e.id for e in executions]))).scalars()
    )
    assert len(rows) == EXECUTIONS
    assert all(row.status == "succeeded" for row in rows)

    # Exactly one "started" transition (and therefore one running marker) per id.
    from app.models.core import AuditRecord

    transitions = dict(
        db.execute(
            select(AuditRecord.resource_id, func.count())
            .where(
                AuditRecord.action == "playbook.execution.started",
                AuditRecord.resource_id.in_(expected_ids),
            )
            .group_by(AuditRecord.resource_id)
        ).all()
    )
    assert transitions == dict.fromkeys(expected_ids, 1)


def test_stale_running_is_reclaimed_while_fresh_lease_is_not_stolen(seeded, db) -> None:
    org = db.get(Organization, seeded["org"].id)
    playbook = _playbook(db, org)
    stale = _execution(db, org, playbook)
    fresh = _execution(db, org, playbook)

    stale.status = "running"
    stale.started_at = utcnow() - timedelta(seconds=playbook_engine.STALE_EXECUTION_SECONDS + 60)
    fresh.status = "running"
    fresh.started_at = utcnow()
    db.commit()

    result = worker_run_once(db, limit=10)
    assert str(stale.id) in result["claimed_ids"]
    assert str(fresh.id) not in result["claimed_ids"]

    db.refresh(stale)
    db.refresh(fresh)
    assert stale.status == "succeeded"
    assert stale.finished_at is not None
    # A live lease is left untouched for its current owner.
    assert fresh.status == "running"
    assert fresh.finished_at is None


def test_worker_startup_failure_leaves_recoverable_failed_state(seeded, db, monkeypatch) -> None:
    org = db.get(Organization, seeded["org"].id)
    playbook = _playbook(db, org)
    execution = _execution(db, org, playbook)

    def explode(*_args, **_kwargs) -> PlaybookExecution:
        raise RuntimeError("startup blew up")

    monkeypatch.setattr(playbook_engine, "advance_execution", explode)
    result = worker_run_once(db, limit=1)

    assert result["claimed"] == 1
    assert result["failed"] == 1
    db.refresh(execution)
    assert execution.status == "failed"
    assert execution.finished_at is not None
    assert "startup blew up" in (execution.error or "")
