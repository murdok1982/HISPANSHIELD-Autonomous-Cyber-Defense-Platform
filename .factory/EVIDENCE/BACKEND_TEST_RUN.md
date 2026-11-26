# Backend verification run — 0.1.3 (2026-11-26)

Environment: Python 3.12.16 (`/tmp/opencode/hs-venv`), PostgreSQL 18.6 at
`127.0.0.1:55432`, database `hispanshield_test`, `HS_ENV=test`.

| Command | Result |
| :--- | :--- |
| `python -m pytest -o addopts="" -q` | see `.factory/EVIDENCE/tests/backend-full.log` |
| `python -m ruff check app tests` | **All checks passed** |
| `python -m ruff format --check app tests` | **248 files already formatted** |
| `python -m mypy app` | **Success: no issues found in 191 source files** |
| `python -m bandit -q -ll -r app -x tests` | exit 0, **0 MEDIUM/HIGH** |
| `python -m pip_audit --skip-editable` | **No known vulnerabilities found** |
| `cd edge && python -m pytest -q -o addopts=""` | **92 passed** |

New regression suites in 0.1.3:

- `tests/integration/test_seed_demo.py` (1) — fresh seed + idempotency.
- `tests/integration/test_outbox_notify.py` (2) — commit-time notify, listener.
- `tests/integration/test_asset_soft_delete.py` (2) — soft delete/restore.
- `tests/integration/test_asm_export.py` (3) — STIX/CSV round-trip.
- `tests/unit/test_scanner_importers.py` (5) — Nessus/OpenVAS/Trivy parsers.
- `tests/integration/test_vuln_importers.py` (4) — normalization/dedupe/XML.
- `tests/integration/test_iec62443_zones.py` (2) — required_sl + compliance gap.

`test_setup.py` was extended to assert the compliance catalogue is populated by
a fresh `/setup`.
