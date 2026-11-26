#!/usr/bin/env python3
"""Durable SOAR execution worker.

Claims pending executions (and waiting executions whose approval has been
decided) with ``FOR UPDATE SKIP LOCKED`` and advances them using the persisted
step state. Safe to run with ``--once`` from cron/systemd or continuously.

Examples:
    python backend/scripts/playbook_worker.py --once
    python backend/scripts/playbook_worker.py --limit 25 --sleep 5
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="HISPANSHIELD durable playbook worker")
    parser.add_argument("--once", action="store_true", help="Process one batch and exit")
    parser.add_argument("--limit", type=int, default=10, help="Maximum executions per batch (1-100)")
    parser.add_argument("--sleep", type=float, default=5.0, help="Idle sleep between batches, in seconds")
    return parser.parse_args()


def main() -> int:
    args = _arguments()
    backend_dir = Path(__file__).resolve().parents[1]
    if str(backend_dir) not in sys.path:
        sys.path.insert(0, str(backend_dir))

    from app.core.db import SessionLocal  # noqa: PLC0415
    from app.core.logging import configure_logging  # noqa: PLC0415
    from app.services.playbook_engine import worker_run_once  # noqa: PLC0415

    configure_logging()
    limit = max(1, min(args.limit, 100))
    while True:
        with SessionLocal() as db:
            result = worker_run_once(db, limit=limit)
        print(json.dumps(result, default=str), flush=True)
        if args.once:
            return 0
        if result["claimed"] == 0 and args.sleep > 0:
            time.sleep(args.sleep)


if __name__ == "__main__":
    raise SystemExit(main())
