"""Database-enforced append-only audit guarantees and hash-scheme integrity."""

from __future__ import annotations

from datetime import timedelta
from uuid import UUID

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import ProgrammingError

from app.core.audit import (
    LEGACY_AUDIT_HASH_VERSION,
    _canonical_payload,
    append_audit,
    verify_audit_chain,
)
from app.core.crypto import sha256_hex
from app.core.db import utcnow
from app.models.core import AuditRecord, Organization


def test_audit_record_cannot_be_updated_or_deleted(seeded, db) -> None:
    org = db.get(Organization, seeded["org"].id)
    record = append_audit(
        db,
        org_id=org.id,
        action="test.append_only",
        resource_type="test",
        actor_type="system",
        payload={"note": "immutable"},
    )
    db.commit()

    with pytest.raises(ProgrammingError):
        db.execute(text("UPDATE audit_records SET action='tampered' WHERE id=:id"), {"id": record.id})
        db.commit()
    db.rollback()

    with pytest.raises(ProgrammingError):
        db.execute(text("DELETE FROM audit_records WHERE id=:id"), {"id": record.id})
        db.commit()
    db.rollback()


def test_audit_table_cannot_be_truncated(seeded, db) -> None:
    with pytest.raises(ProgrammingError):
        db.execute(text("TRUNCATE audit_records"))
        db.commit()
    db.rollback()


def _insert_legacy_v1_record(
    db,
    org: Organization,
    *,
    action: str = "legacy.append",
    actor_email: str = "legacy@hispanshield.eu",
    created_at=None,
) -> AuditRecord:
    """Persist a record exactly as the pre-hardening v1 writer would have."""
    timestamp = created_at or (utcnow() - timedelta(days=365))
    payload = {"note": "legacy record"}
    canonical = _canonical_payload(
        org.id,
        "user",
        "legacy-actor",
        actor_email,
        action,
        "test",
        "legacy-resource",
        "success",
        payload,
        timestamp,
        version=LEGACY_AUDIT_HASH_VERSION,
    )
    record = AuditRecord(
        org_id=org.id,
        actor_type="user",
        actor_id="legacy-actor",
        actor_email=actor_email,
        action=action,
        resource_type="test",
        resource_id="legacy-resource",
        outcome="success",
        # Legacy writers stored these columns but did not hash them.
        request_id="legacy-request-id",
        ip_address="203.0.113.50",
        user_agent="legacy-agent/1.0",
        payload=payload,
        prev_hash=None,
        hash=sha256_hex(canonical),
        created_at=timestamp,
    )
    db.add(record)
    db.flush()
    return record


def _tamper(db, record_id: UUID, column: str, value: str) -> None:
    assert column in {"request_id", "ip_address", "user_agent", "actor_email", "payload"}
    db.execute(text("ALTER TABLE audit_records DISABLE TRIGGER audit_records_append_only"))
    try:
        db.execute(
            text(f"UPDATE audit_records SET {column} = :value WHERE id = :id"),
            {"value": value, "id": record_id},
        )
        db.commit()
    finally:
        db.execute(text("ALTER TABLE audit_records ENABLE TRIGGER audit_records_append_only"))
        db.commit()


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("request_id", "tampered-request-id"),
        ("ip_address", "198.51.100.99"),
        ("user_agent", "tampered-agent/9.9"),
        ("actor_email", "attacker@example.eu"),
    ],
)
def test_v2_hash_covers_request_metadata(seeded, db, column: str, value: str) -> None:
    org = db.get(Organization, seeded["org"].id)
    record = append_audit(
        db,
        org_id=org.id,
        action="test.request_metadata",
        resource_type="test",
        actor_type="user",
        actor_id="actor-1",
        actor_email="actor@hispanshield.eu",
        request_id="req-123456",
        ip_address="203.0.113.7",
        user_agent="hispanshield-test/1.0",
        payload={"note": "covered by v2"},
    )
    db.commit()

    verified = verify_audit_chain(db, org.id)
    assert verified["valid"] is True
    assert verified["schemes"]["v2"] >= 1

    _tamper(db, record.id, column, value)
    broken = verify_audit_chain(db, org.id)
    assert broken["valid"] is False
    assert broken["broken_at"] == str(record.id)
    assert broken["reason"] == "hash mismatch"


def test_legacy_v1_records_still_verify(seeded, db) -> None:
    org = Organization(slug="audit-legacy", name="Audit Legacy Org")
    db.add(org)
    db.commit()

    legacy = _insert_legacy_v1_record(db, org)
    db.commit()
    current = append_audit(
        db,
        org_id=org.id,
        action="test.after_legacy",
        resource_type="test",
        actor_type="system",
        request_id="req-after-legacy",
        ip_address="203.0.113.8",
        user_agent="hispanshield-test/2.0",
    )
    db.commit()

    assert current.prev_hash == legacy.hash
    verified = verify_audit_chain(db, org.id)
    assert verified["valid"] is True
    assert verified["checked"] == 2
    assert verified["schemes"] == {"v1": 1, "v2": 1}
    assert verified["head"] == current.hash

    # A legacy record still detects tampering of fields it did cover.
    _tamper(db, legacy.id, "actor_email", "attacker@example.eu")
    broken = verify_audit_chain(db, org.id)
    assert broken["valid"] is False
    assert broken["broken_at"] == str(legacy.id)


def test_append_chains_prev_hash_across_schemes(seeded, db) -> None:
    org = db.get(Organization, seeded["org"].id)
    first = append_audit(
        db,
        org_id=org.id,
        action="test.chain.first",
        resource_type="test",
        actor_type="system",
        request_id="req-first",
        ip_address="203.0.113.9",
        user_agent="agent/1",
    )
    db.flush()
    second = append_audit(
        db,
        org_id=org.id,
        action="test.chain.second",
        resource_type="test",
        actor_type="system",
        request_id="req-second",
        ip_address="203.0.113.10",
        user_agent="agent/2",
    )
    db.commit()

    records = list(
        db.execute(
            select(AuditRecord).where(AuditRecord.org_id == org.id).order_by(AuditRecord.created_at.asc())
        ).scalars()
    )
    second_index = next(index for index, item in enumerate(records) if item.id == second.id)
    assert records[second_index - 1].id == first.id
    assert second.prev_hash == first.hash

    verified = verify_audit_chain(db, org.id)
    assert verified["valid"] is True
    assert verified["head"] == records[-1].hash
