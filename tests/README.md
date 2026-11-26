# Test suites

HISPANSHIELD keeps tests close to the domain that owns them, plus a small
cross-cutting acceptance layer.

| Suite | Location | Command | Scope |
| :--- | :--- | :--- | :--- |
| Backend unit/integration/security | `backend/tests/` | `cd backend && pytest -q` | Auth, tenancy, RBAC, audit, assets, vulns, SIEM, incidents, SOAR, defence guardrails, connectors, AI/agents/MCP, edge, forensics, compliance, reports, HTTP hardening |
| Frontend unit/component | `frontend/src/pages/__tests__/` | `cd frontend && npm run test` | Validation helpers, lifecycle/SLA, risk formatting, protocol grouping, compliance/permission states |
| Frontend E2E | `frontend/e2e/` | `cd frontend && npm run test:e2e` | All 24 screens, critical flows, no console/HTTP 4xx-5xx errors, mobile overflow |
| Edge agent | `edge/tests/` | `cd edge && pytest -q` | SQLite durability, HMAC signature parity, offline flush, replay, config integrity, collectors |
| Autonomy lab | `backend/tests/security/test_autonomy_guardrails.py` | `cd backend && pytest -q tests/security/test_autonomy_guardrails.py` | Allow/deny by level, approvals, kill switch, OT block, forbidden actions, rollback |
| Prompt/tool injection | `backend/tests/unit/test_prompt_safety.py`, `backend/tests/integration/test_mcp.py` | `cd backend && pytest -q tests/unit/test_prompt_safety.py tests/integration/test_mcp.py` | Override attempts, untrusted delimiters, MCP allowlist, schema validation |

## Databases

Backend tests require PostgreSQL. `backend/tests/conftest.py` builds the schema
with Alembic and truncates between tests. Set a dedicated test database:

```bash
export HS_DATABASE_URL="postgresql+psycopg://hispanshield:password@localhost:5432/hispanshield_test"
cd backend && pytest -q
```

The fixture temporarily disables the audit append-only triggers to truncate, as
the schema owner. This does not weaken production behaviour; there is an
explicit regression test proving UPDATE/DELETE/TRUNCATE are blocked.

## Evidence

- Backend: one passing suite on a real PostgreSQL instance.
- Frontend: `tsc -b` + `vite build` + Vitest + Playwright.
- Security: `pip-audit`, `bandit`, secret scan, and the adversarial report in
  `.factory/SECURITY_AUDIT.md`.
- Supply chain: SBOM via `scripts/sbom.sh` and CI workflow.

Tests never call the public Internet: connectors, AI providers, feeds and MCP
servers are simulated with local ephemeral HTTP servers. Destructive autonomy
tests use registered test adapters, never real firewalls or OT devices.
