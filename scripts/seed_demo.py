"""Load the labelled demonstration dataset (refuses in production)."""

from __future__ import annotations

import os
import sys

os.environ.setdefault("HS_SEED_DEMO", "true")

from app.seed import main  # noqa: E402

if __name__ == "__main__":
    try:
        main()
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from exc
