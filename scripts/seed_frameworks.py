"""Idempotently load the built-in compliance framework catalogue.

A fresh installation seeded through ``POST /api/v1/setup`` already loads the
catalogue. This script exists for existing deployments that upgrade to a
release where the catalogue was not seeded yet, and for operational recovery.

Usage:
    HS_DATABASE_URL=... python scripts/seed_frameworks.py
"""

from __future__ import annotations

import sys

from app.core.db import SessionLocal
from app.modules.compliance.service import seed_builtin_frameworks


def main() -> int:
    with SessionLocal() as db:
        result = seed_builtin_frameworks(db)
    print(
        f"Compliance catalogue: {result['created']} created, "
        f"{result['skipped']} already present, {result['total']} built-in documents"
    )
    for framework in result["frameworks"]:
        print(f"  - {framework['code']} {framework['version']}: {framework['status']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
