"""Create the first platform administrator from environment variables."""

from __future__ import annotations

import argparse
import os
import sys

from app.core.config import settings
from app.core.db import SessionLocal
from app.services.bootstrap import BootstrapError, bootstrap_admin


def main() -> int:
    parser = argparse.ArgumentParser(description="Bootstrap the HISPANSHIELD platform administrator")
    parser.add_argument("--email", default=os.environ.get("HS_BOOTSTRAP_ADMIN_EMAIL"))
    parser.add_argument("--password", default=os.environ.get("HS_BOOTSTRAP_ADMIN_PASSWORD"))
    parser.add_argument("--name", default="Platform Administrator")
    parser.add_argument("--org", default=settings.bootstrap_org_name)
    parser.add_argument("--org-slug", default=None)
    parser.add_argument("--org-kind", default="private", choices=["private", "public", "critical_infrastructure"])
    parser.add_argument(
        "--promote-existing",
        action="store_true",
        help="Explicitly elevate an existing non-admin account (requires prior review)",
    )
    args = parser.parse_args()

    if not args.email or not args.password:
        print("HS_BOOTSTRAP_ADMIN_EMAIL and HS_BOOTSTRAP_ADMIN_PASSWORD are required", file=sys.stderr)
        return 2

    with SessionLocal() as db:
        try:
            user, org, created = bootstrap_admin(
                db,
                email=args.email,
                password=args.password,
                full_name=args.name,
                org_name=args.org,
                org_slug=args.org_slug,
                org_kind=args.org_kind,
                promote_existing=args.promote_existing,
            )
        except BootstrapError as exc:
            print(str(exc), file=sys.stderr)
            return 1

    print(f"Administrator ready: {user.email}")
    print(f"Organization: {org.name} (slug={org.slug}, id={org.id})")
    print(f"Account created: {created}")
    print("Remove HS_BOOTSTRAP_ADMIN_PASSWORD from the environment after this step.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
