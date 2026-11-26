"""Seed global reference catalogues (compliance, agents, detection rules).

Idempotent and safe to run on every deployment. Does not create organizations or
demo data. Run after `alembic upgrade head`:

    cd backend && python scripts/seed_reference_data.py
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
from app.modules.agents.seed import seed_agent_catalog  # noqa: E402
from app.modules.compliance.service import seed_builtin_frameworks  # noqa: E402
from scripts.seed_siem import builtin_rules, seed_builtin_rules  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed global HISPANSHIELD reference data")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    with SessionLocal() as db:
        compliance = seed_builtin_frameworks(db)
        agents = seed_agent_catalog(db)
        created_rules = seed_builtin_rules(db, created_by="seed-reference")
        rules = {"created": len(created_rules), "total": len(builtin_rules())}
        db.commit()

    summary = {"compliance": compliance, "agents": agents, "detection_rules": rules}
    if args.json:
        print(json.dumps(summary, indent=2, default=str))
    else:
        print(f"Compliance: {compliance.get('created', 0)} created / {compliance.get('total', 0)} total")
        print(f"Agents: {agents.get('created', 0)} created / {agents.get('total', 0)} total")
        print(f"Detection rules: {rules.get('created', 0)} created / {rules.get('total', 0)} total")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
