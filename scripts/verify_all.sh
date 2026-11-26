#!/usr/bin/env bash
# HISPANSHIELD release gate. Run from the repository root.
# Some checks need a running server/seed (E2E) and are opt-in via HS_E2E=1.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-python3}"
if [[ -x "$ROOT/.venv/bin/python" ]]; then PYTHON="$ROOT/.venv/bin/python"; fi
NODE="${NODE:-node}"
if ! command -v "$NODE" >/dev/null 2>&1 && [[ -x /tmp/opencode/node-v22.14.0-linux-x64/bin/node ]]; then
  NODE=/tmp/opencode/node-v22.14.0-linux-x64/bin/node
fi

echo "== Backend lint, format and types =="
(cd backend && "$PYTHON" -m ruff check app tests && "$PYTHON" -m ruff format --check app tests && "$PYTHON" -m mypy app)

echo "== Backend tests (PostgreSQL required) =="
(cd backend && "$PYTHON" -m pytest -q)

echo "== Edge agent tests =="
(cd edge && "$PYTHON" -m pytest -q)

echo "== Frontend types, production build and unit tests =="
(cd frontend && "$NODE" node_modules/typescript/bin/tsc -b --force && "$NODE" node_modules/vite/bin/vite.js build && "$NODE" node_modules/vitest/vitest.mjs run)

echo "== Dependency audit (runtime + development) =="
(cd backend && "$PYTHON" -m pip_audit --skip-editable)
if command -v npm >/dev/null 2>&1; then
  (cd frontend && npm audit --audit-level=high)
else
  echo "npm not found; skipping frontend audit"
fi

echo "== Static security scan (blocking medium/high) =="
(cd backend && "$PYTHON" -m bandit -q -ll -r app -x tests)

echo "== Secret scan (tracked files) =="
if git grep -nEI 'BEGIN (RSA|OPENSSH|EC|PGP) PRIVATE KEY|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|xox[baprs]-|sk-[A-Za-z0-9]{20,}' -- . \
  ':!docs/**' ':!specs/**' ':!backend/tests/**' ':!edge/tests/**' ':!frontend/src/pages/__tests__/**'; then
  echo "Potential secret found" >&2
  exit 1
else
  echo "No hardcoded secret patterns found"
fi

if [[ "${HS_E2E:-0}" == "1" ]]; then
  echo "== Playwright E2E (requires a seeded server at HS_E2E_BASE_URL) =="
  (cd frontend && "$NODE" node_modules/@playwright/test/cli.js test e2e --project=chromium-desktop)
fi

echo "== Gate PASS =="
