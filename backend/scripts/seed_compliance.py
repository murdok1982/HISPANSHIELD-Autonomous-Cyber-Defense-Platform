"""Seed the built-in compliance framework catalogue.

Usage (from backend/):

    python scripts/seed_compliance.py

Idempotent: frameworks are keyed by (code, version) and existing rows are not
modified. Safe to run on every deployment.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.core.db import SessionLocal  # noqa: E402
from app.modules.compliance.service import seed_builtin_frameworks  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed built-in compliance frameworks")
    parser.add_argument("--json", action="store_true", help="Print the seed summary as JSON")
    args = parser.parse_args()

    with SessionLocal() as db:
        result = seed_builtin_frameworks(db)

    if args.json:
        print(json.dumps(dict(result), indent=2, default=str))
    else:
        print(
            f"Frameworks: {result['total']} documents, {result['created']} created, "
            f"{result['skipped']} already present."
        )
        for item in result["frameworks"]:
            print(f"  - {item['code']} {item['version']}: {item['status']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
