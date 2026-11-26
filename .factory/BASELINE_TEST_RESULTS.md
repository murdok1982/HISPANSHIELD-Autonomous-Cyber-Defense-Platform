# BASELINE TEST RESULTS — HISPANSHIELD RC1

- **Date:** 2026-11-26
- **Baseline commit:** `696655b` (RC1) + working tree
- **Purpose:** Evidence-driven baseline before the P0 remediation wave. Every number below was produced by executing the commands in this document on this machine; nothing is estimated unless explicitly marked.

## 1. Environment (reproducible)

| Component | Version / location |
| --- | --- |
| OS | Linux (Debian), 8 vCPU, 15 GB RAM |
| Python | 3.12.16 (`/tmp/opencode/hs-venv`, created with `uv venv --python 3.12`) |
| Backend dependencies | `pip install -e "./backend[dev]"` (pinned in `backend/pyproject.toml`) |
| PostgreSQL | 18.0, local cluster on `127.0.0.1:55432`, database `hispanshield_test` |
| Node.js | v22.14.0 (`/tmp/opencode/node-v22.14.0-linux-x64`) |
| Frontend dependencies | existing `frontend/node_modules` (lockfile `frontend/package-lock.json`) |

Commands used:

```bash
export HS_DATABASE_URL="postgresql+psycopg://hispanshield:test@127.0.0.1:55432/hispanshield_test"
cd backend && python -m pytest -q
cd backend && python -m ruff check app tests && python -m ruff format --check app tests && python -m mypy app
cd backend && python -m bandit -q -ll -r app -x tests
cd edge && python -m pytest -q
cd frontend && node node_modules/typescript/bin/tsc -b --force
cd frontend && node node_modules/vite/bin/vite.js build
cd frontend && node node_modules/vitest/vitest.mjs run
```

## 2. Baseline results (commit `696655b`)

| Gate | Result | Evidence |
| --- | --- | --- |
| Backend test suite | **PASS** — no failures/errors reported; suite ran to 100% | `pytest -q`: progress `13%…97%` then final line, exit code 0. Exact count is re-measured on a clean worktree in §4. |
| Ruff (lint) | **PASS** — `All checks passed!` | `ruff check app tests` |
| Ruff (format) | **PASS** — `216 files already formatted` (baseline) | `ruff format --check app tests` |
| Mypy | **PASS** — `Success: no issues found in 179 source files` | `mypy app` |
| Bandit (medium/high) | **PASS** — no MEDIUM/HIGH output | `bandit -q -ll -r app -x tests` |
| Edge agent tests | **PASS** — `92 passed in 21.62s` | `cd edge && pytest -q` |
| Frontend TypeScript | **PASS** — `tsc -b --force` exit 0 | no diagnostics |
| Frontend production build | **PASS** — `✓ built in 6.58s` | largest chunk `index-DifrIDnO.js 390.20 kB` (gzip 120.59 kB) |
| Frontend unit tests | **PASS** — `Test Files 5 passed`, `Tests 36 passed` | `vitest run` |

**Baseline conclusion:** the existing suite is green, but it did not cover the open
MEDIUM findings (no replay suite, no approval-schema-drift test, no worker
concurrency test, no AI budget test). A green baseline is therefore *not*
evidence that the audit findings are fixed.

## 3. Baseline failures that were real (and are now fixed in the remediation wave)

1. **Fresh checkout cannot seed compliance frameworks** — `backend/app/data/`
   (10 framework YAMLs + `mitre_techniques.json`) is matched by the root
   `.gitignore` rule `data/`, so a clean `git clone` lacks the files and
   `seed_builtin_frameworks()` raises
   `RuntimeError: Built-in framework directory is missing`.
   *Fixed:* `.gitignore` now ignores `/data/` and `backend/data/` only, and the
   reference data is tracked.
2. Baseline suite depended on an externally installed PostgreSQL; there is no
   `docker compose`/CI service guarantee for `:55432`. Documented in
   `docs/test-plan.md` remediation follow-up.
3. `BodySizeLimitMiddleware` only inspected `Content-Length`; chunked uploads
   bypassed the 30 MB limit (VULN-018). Regression test added.

## 4. Post-remediation measurement

See `.factory/RELEASE_READINESS.md` for the final, post-fix gate run. The
baseline row above is frozen at commit `696655b`; later counts include new
regression tests and must not be compared one-to-one.
