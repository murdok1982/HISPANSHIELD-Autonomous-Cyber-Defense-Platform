"""Database-enforced append-only audit guarantees."""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError

from app.core.audit import append_audit
from app.models.core import Organization


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
