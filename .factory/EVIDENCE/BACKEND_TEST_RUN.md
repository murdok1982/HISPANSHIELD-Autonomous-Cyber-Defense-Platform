# Backend verification run — 2026-11-26

Environment: Python 3.14.10 (host), PostgreSQL 18.6 at `127.0.0.1:55432`,
database `hispanshield_test` created for this run. The project targets Python
3.12; CI runs 3.12.

| Command | Result |
| :--- | :--- |
| `python -m pytest -o addopts="" -q` | **650 passed, 2 warnings in 241.85s** |
| `uvx ruff@0.11.10 check app tests` | **All checks passed** |
| `uvx ruff@0.11.10 format --check app tests` | **238 files already formatted** |
| `uvx --with types-PyYAML mypy@1.15.0 app` | **Success: no issues found in 188 source files** |
| `uvx bandit@1.8.3 -q -ll -r app -x tests` | exit 0, no MEDIUM/HIGH |
| `uvx pip-audit@2.9.0 --skip-editable` | **No known vulnerabilities found** |
| `cd edge && python -m pytest -q -o addopts=""` | **92 passed** |

Warnings (non-failing, pre-existing):

- `pytest_asyncio` loop-scope deprecation.
- Pydantic `UnsupportedFieldAttributeWarning` in `test_siem.py` for
  `validation_alias` inside an `Annotated` union; it does not affect the tests.

New regression suites included in the 650:

- `tests/security/test_audit_hmac.py` (6)
- `tests/integration/test_outbox.py` (10)
- `tests/integration/test_sse.py` (5)
- `tests/integration/test_cursor_pagination.py` (5)
- `tests/integration/test_idempotency.py` (7)
- `tests/integration/test_setup.py` (2)
- `tests/integration/test_invitations.py` (4)
- `tests/integration/test_auth_policy.py` (2)
