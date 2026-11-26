"""Idempotent SIEM seeder: global builtin rules + one default ingest source.

Usage (inside ``backend/``)::

    /tmp/opencode/hs-venv/bin/python scripts/seed_siem.py --org-slug acme

Running it repeatedly never duplicates rules or rotates an existing token.  The
raw ingestion token is printed exactly once, on creation.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from sqlalchemy import select

from app.core.audit import append_audit
from app.core.db import SessionLocal
from app.models.core import Organization
from app.models.events import DetectionRule, IngestSource
from app.modules.events.service import create_source
from app.modules.siem.builtin_rules import builtin_rules

DEFAULT_SOURCE_NAME = "Default API ingestion"


def seed_builtin_rules(db: Any, *, org_id: Any = None, created_by: str = "seed-siem") -> list[DetectionRule]:
    """Insert missing builtin rules into the global (or given org) scope."""
    org_filter = DetectionRule.org_id.is_(None) if org_id is None else DetectionRule.org_id == org_id
    existing = {name for (name,) in db.execute(select(DetectionRule.name).where(org_filter)).all()}
    created: list[DetectionRule] = []
    for spec in builtin_rules():
        if spec["name"] in existing:
            continue
        rule = DetectionRule(
            org_id=org_id,
            name=spec["name"],
            description=spec["description"],
            severity=spec["severity"],
            status="production",
            enabled=True,
            version=1,
            logsource=spec["logsource"],
            definition=spec["definition"],
            mitre=spec["mitre"],
            tags=spec["tags"],
            created_by=created_by,
        )
        db.add(rule)
        created.append(rule)
    db.flush()
    return created


def seed_default_source(
    db: Any,
    *,
    org: Organization,
    name: str = DEFAULT_SOURCE_NAME,
    created_by: str = "seed-siem",
) -> tuple[IngestSource, str | None]:
    """Create the default API source once; returns ``(source, raw_token_or_None)``."""
    existing = db.execute(
        select(IngestSource).where(IngestSource.org_id == org.id, IngestSource.name == name)
    ).scalar_one_or_none()
    if existing is not None:
        return existing, None
    source, raw_token, _secret = create_source(
        db,
        org_id=org.id,
        name=name,
        kind="api",
        parser="auto",
        enabled=True,
        config={"seeded": True},
        created_by=created_by,
    )
    return source, raw_token


def seed_siem(
    db: Any,
    *,
    org: Organization | None = None,
    with_source: bool = False,
    source_name: str = DEFAULT_SOURCE_NAME,
    created_by: str = "seed-siem",
    commit: bool = True,
) -> dict[str, Any]:
    """Seed global rules and optionally a default source for ``org``."""
    created_rules = seed_builtin_rules(db, created_by=created_by)
    source: IngestSource | None = None
    raw_token: str | None = None
    if with_source and org is not None:
        source, raw_token = seed_default_source(db, org=org, name=source_name, created_by=created_by)
    append_audit(
        db,
        org_id=org.id if org else None,
        action="siem.seed",
        resource_type="detection_rule",
        actor_type="system",
        actor_id=created_by,
        payload={
            "rules_created": len(created_rules),
            "source_created": bool(raw_token),
            "source_id": str(source.id) if source else None,
        },
    )
    if commit:
        db.commit()
    return {
        "rules_created": len(created_rules),
        "rules_total": len(builtin_rules()),
        "source_id": str(source.id) if source else None,
        "source_name": source.name if source else None,
        "source_token": raw_token,
        "source_created": raw_token is not None,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Seed builtin SIEM rules and a default ingest source")
    parser.add_argument("--org-slug", required=True, help="Organization slug that receives the default source")
    parser.add_argument("--no-source", action="store_true", help="Only seed global builtin rules")
    parser.add_argument("--source-name", default=DEFAULT_SOURCE_NAME)
    args = parser.parse_args(argv)

    with SessionLocal() as db:
        org = db.execute(
            select(Organization).where(
                Organization.slug == args.org_slug,
                Organization.deleted_at.is_(None),
            )
        ).scalar_one_or_none()
        if org is None:
            print(f"Organization not found: {args.org_slug}", file=sys.stderr)
            return 2
        summary = seed_siem(
            db,
            org=org,
            with_source=not args.no_source,
            source_name=args.source_name,
            commit=False,
        )
        db.commit()
    print(json.dumps(summary, indent=2, default=str))
    if summary["source_token"]:
        print("Store this ingestion token now; it will not be shown again.", file=sys.stderr)
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    raise SystemExit(main())


__all__ = ["DEFAULT_SOURCE_NAME", "seed_builtin_rules", "seed_default_source", "seed_siem"]
