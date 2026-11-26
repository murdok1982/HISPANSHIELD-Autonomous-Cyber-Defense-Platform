"""Seed the defensive agent catalogue idempotently.

Examples:
    cd backend && PYTHONPATH=. python scripts/seed_agents.py
    cd backend && PYTHONPATH=. python scripts/seed_agents.py --org-slug my-org --all-organizations
"""

from __future__ import annotations

import argparse
import sys

from sqlalchemy import select

from app.core.db import SessionLocal
from app.models.core import Organization
from app.modules.agents.seed import seed_agent_catalog, seed_all_organizations


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed the HISPANSHIELD agent catalogue")
    parser.add_argument("--org-slug", default=None, help="Seed an organization-specific copy of the catalogue")
    parser.add_argument(
        "--all-organizations",
        action="store_true",
        help="Seed the global catalogue and an organization-specific copy for every active organization",
    )
    args = parser.parse_args()

    with SessionLocal() as db:
        if args.all_organizations:
            stats = seed_all_organizations(db)
            db.commit()
            print(f"Global catalogue: created={stats['global']['created']} updated={stats['global']['updated']}")
            print(f"Organizations seeded: {stats['organizations']}")
            return 0

        global_stats = seed_agent_catalog(db, None)
        print(f"Global catalogue: created={global_stats['created']} updated={global_stats['updated']}")
        if args.org_slug:
            organization = db.execute(
                select(Organization).where(Organization.slug == args.org_slug, Organization.deleted_at.is_(None))
            ).scalar_one_or_none()
            if organization is None:
                db.rollback()
                print(f"Organization not found: {args.org_slug}", file=sys.stderr)
                return 1
            stats = seed_agent_catalog(db, organization.id)
            print(f"Organization {organization.slug}: created={stats['created']} updated={stats['updated']}")
        db.commit()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
