"""Fresh-install demo seeding must not violate ingest dedupe or leave compliance empty."""

from __future__ import annotations

from sqlalchemy import func, select

from app.core.config import settings
from app.models.compliance import ComplianceFramework
from app.models.core import Organization
from app.models.events import SecurityEvent
from app.seed import DEMO_SLUG, seed_demo


def test_demo_seed_is_fresh_install_safe_and_idempotent(db, monkeypatch) -> None:
    monkeypatch.setattr(settings, "seed_demo", True, raising=False)

    org, created = seed_demo(db)
    assert created is True
    assert org.slug == DEMO_SLUG

    events = db.execute(select(func.count()).select_from(SecurityEvent)).scalar_one()
    distinct_keys = db.execute(select(func.count(func.distinct(SecurityEvent.dedupe_key)))).scalar_one()
    assert events > 0
    # Repeated message/host/user tuples in different minutes must still get a
    # unique ingest dedupe key, otherwise a fresh seed aborts on
    # uq_events_org_dedupe.
    assert distinct_keys == events

    frameworks = db.execute(select(func.count()).select_from(ComplianceFramework)).scalar_one()
    assert frameworks >= 10

    again, created_again = seed_demo(db)
    assert created_again is False
    assert again.id == org.id
    assert db.execute(select(func.count()).select_from(Organization)).scalar_one() >= 1
