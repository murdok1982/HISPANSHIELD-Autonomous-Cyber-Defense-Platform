"""Audit integrity v3: HMAC key custody, rotation and signed checkpoints."""

from __future__ import annotations

from sqlalchemy import select, text

from app.core.audit import (
    HMAC_AUDIT_HASH_VERSION,
    append_audit,
    create_audit_checkpoint,
    verify_audit_chain,
    verify_audit_checkpoint,
)
from app.core.config import settings
from app.models.core import AuditCheckpoint, AuditRecord, Organization

SECRET_A = "audit-key-a-0123456789-abcdefghijklmnopqrstuvwxyz"
SECRET_B = "audit-key-b-0123456789-abcdefghijklmnopqrstuvwxyz"


def _enable(monkeypatch, key: str, key_id: str, previous: str = "") -> None:
    monkeypatch.setattr(settings, "audit_hmac_key", key, raising=False)
    monkeypatch.setattr(settings, "audit_hmac_key_id", key_id, raising=False)
    monkeypatch.setattr(settings, "audit_hmac_previous_keys", previous, raising=False)


def _disable(monkeypatch) -> None:
    monkeypatch.setattr(settings, "audit_hmac_key", "", raising=False)
    monkeypatch.setattr(settings, "audit_hmac_previous_keys", "", raising=False)


def test_hmac_chain_verifies_and_detects_tampering(seeded, db, monkeypatch) -> None:
    _enable(monkeypatch, SECRET_A, "k1")
    org = db.get(Organization, seeded["org"].id)
    first = append_audit(db, org_id=org.id, action="v3.first", resource_type="test", actor_type="system")
    second = append_audit(
        db,
        org_id=org.id,
        action="v3.second",
        resource_type="test",
        actor_type="system",
        payload={"n": 2},
    )
    db.commit()
    assert first.hash_version == HMAC_AUDIT_HASH_VERSION
    assert first.key_id == "k1"
    assert second.prev_hash == first.hash
    assert verify_audit_chain(db, org.id)["schemes"]["v3"] == 2

    # A database-only attacker can edit rows but cannot recompute the HMAC.
    db.execute(text("ALTER TABLE audit_records DISABLE TRIGGER audit_records_append_only"))
    try:
        db.execute(text("UPDATE audit_records SET payload = '{\"tampered\": true}' WHERE id = :id"), {"id": second.id})
        db.commit()
    finally:
        db.execute(text("ALTER TABLE audit_records ENABLE TRIGGER audit_records_append_only"))
        db.commit()
    result = verify_audit_chain(db, org.id)
    assert result["valid"] is False
    assert result["reason"] == "HMAC hash mismatch"


def test_key_rotation_keeps_old_segments_verifiable(seeded, db, monkeypatch) -> None:
    _enable(monkeypatch, SECRET_A, "k1")
    org = db.get(Organization, seeded["org"].id)
    append_audit(db, org_id=org.id, action="v3.before-rotation", resource_type="test", actor_type="system")
    db.commit()

    _enable(monkeypatch, SECRET_B, "k2", previous=f"k1:{SECRET_A}")
    rotated = append_audit(db, org_id=org.id, action="v3.after-rotation", resource_type="test", actor_type="system")
    db.commit()
    assert rotated.key_id == "k2"

    result = verify_audit_chain(db, org.id)
    assert result["valid"] is True
    assert result["schemes"]["v3"] == 2

    # Removing the retired key makes the old segment unverifiable: that is the
    # intended failure mode, not a silent "valid".
    _enable(monkeypatch, SECRET_B, "k2")
    broken = verify_audit_chain(db, org.id)
    assert broken["valid"] is False
    assert "unknown audit HMAC key" in broken["reason"]


def test_signed_checkpoint_anchors_the_chain_and_verifies(seeded, db, monkeypatch) -> None:
    _enable(monkeypatch, SECRET_A, "k1")
    org = db.get(Organization, seeded["org"].id)
    append_audit(db, org_id=org.id, action="checkpoint.seed", resource_type="test", actor_type="system")
    db.commit()

    checkpoint, chain = create_audit_checkpoint(db, org.id)
    db.commit()
    assert checkpoint is not None
    assert chain["valid"] is True
    assert checkpoint.record_count >= 1
    assert verify_audit_checkpoint(checkpoint) is True

    stored = db.execute(select(AuditCheckpoint).where(AuditCheckpoint.id == checkpoint.id)).scalar_one()
    stored.signature = "0" * 64
    db.commit()
    assert verify_audit_checkpoint(stored) is False


def test_checkpoint_is_not_faked_without_a_key(seeded, db, monkeypatch) -> None:
    _disable(monkeypatch)
    org = db.get(Organization, seeded["org"].id)
    append_audit(db, org_id=org.id, action="no-key", resource_type="test", actor_type="system")
    db.commit()
    checkpoint, chain = create_audit_checkpoint(db, org.id)
    assert checkpoint is None
    assert chain["valid"] is True
    assert chain["checkpoint"] == "not_created"
    assert db.execute(select(AuditCheckpoint)).first() is None


def test_unknown_key_id_invalidates_the_chain(seeded, db, monkeypatch) -> None:
    _enable(monkeypatch, SECRET_A, "k1")
    org = db.get(Organization, seeded["org"].id)
    record = append_audit(db, org_id=org.id, action="unknown-key", resource_type="test", actor_type="system")
    db.commit()
    db.execute(text("ALTER TABLE audit_records DISABLE TRIGGER audit_records_append_only"))
    try:
        db.execute(text("UPDATE audit_records SET key_id = 'ghost' WHERE id = :id"), {"id": record.id})
        db.commit()
    finally:
        db.execute(text("ALTER TABLE audit_records ENABLE TRIGGER audit_records_append_only"))
        db.commit()
    result = verify_audit_chain(db, org.id)
    assert result["valid"] is False
    assert "ghost" in result["reason"]


def test_legacy_v2_records_still_verify_when_hmac_is_enabled(seeded, db, monkeypatch) -> None:
    _disable(monkeypatch)
    org = db.get(Organization, seeded["org"].id)
    legacy = append_audit(db, org_id=org.id, action="v2.legacy", resource_type="test", actor_type="system")
    db.commit()
    assert legacy.hash_version == 2
    before = verify_audit_chain(db, org.id)["schemes"]

    _enable(monkeypatch, SECRET_A, "k1")
    modern = append_audit(db, org_id=org.id, action="v3.modern", resource_type="test", actor_type="system")
    db.commit()
    assert modern.key_id == "k1"
    result = verify_audit_chain(db, org.id)
    assert result["valid"] is True
    assert result["schemes"]["v2"] == before["v2"]
    assert result["schemes"]["v3"] == 1


def test_audit_records_expose_version_and_key_id(seeded, db, monkeypatch) -> None:
    _enable(monkeypatch, SECRET_A, "k1")
    org = db.get(Organization, seeded["org"].id)
    record = append_audit(db, org_id=org.id, action="v3.columns", resource_type="test", actor_type="system")
    db.commit()
    row = db.execute(select(AuditRecord).where(AuditRecord.id == record.id)).scalar_one()
    assert row.hash_version == 3
    assert row.key_id == "k1"
