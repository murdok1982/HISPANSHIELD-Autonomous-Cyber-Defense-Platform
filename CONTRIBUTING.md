# Contributing to HISPANSHIELD

This repository follows Spec-Driven Development. No feature is complete without
a specification, tests and evidence.

## 1. Before you code

1. Read `specs/constitution.md` and the relevant domain specification.
2. Check `.factory/TASKS.md` for the atomic task and dependencies.
3. Read the ADRs that constrain your area (`specs/adr/`).
4. For UI work, read `docs/frontend-conventions.md`.
5. For backend work, read `docs/backend-conventions.md`.

## 2. Non-negotiable rules

- Zero placeholders: no `TODO`, mock telemetry, dead buttons or empty endpoints.
- Never weaken a security control to make a test pass.
- Every mutation is authorized server-side, tenant-scoped and audited.
- No secrets in the repository. Use `HS_*` environment variables or the
  encrypted secret store.
- AI output is advisory. Execution authority belongs to the policy engine,
  authorization service and execution broker, never to a model.
- Defensive actions must be catalogued, reversible when technically possible,
  approved when required and verified afterwards.
- OT/IoT is passive by default. Never add active scans, controller writes,
  reboots or firmware updates.
- No offensive capability: no exploitation, credential theft, destructive
  payloads or operations outside an authorized scope.

## 3. Development workflow

```bash
# Backend
cd backend
ruff format app tests
ruff check app tests
mypy app
pytest -q

# Frontend
cd frontend
node node_modules/typescript/bin/tsc -b
node node_modules/vitest/vitest.mjs run
node node_modules/vite/bin/vite.js build
```

Database changes require an Alembic migration. Never use `create_all` as the
production evolution mechanism. Destructive migrations require a rollback plan.

## 4. Pull requests

- One domain per PR where possible; keep diffs reviewable.
- Include: specification reference, acceptance criteria, tests run, security
  impact, migration notes, screenshots for UI changes.
- Update `docs/implementation-status.md` with the new state and evidence.
- Security-sensitive changes (auth, tenancy, autonomy, connectors, crypto)
  require an independent reviewer. No self-approval.
- Do not commit generated evidence, dumps, `.env` files or connector secrets.

## 5. Commit messages

Conventional Commits, imperative mood, scope:

```text
feat(assets): add authorized passive discovery import
fix(auth): reject cross-tenant organization headers
docs(adr): justify PostgreSQL workflow engine for MVP
```

## 6. Security disclosure

Follow `SECURITY.md`. Do not open public issues for vulnerabilities.

## 7. License

By contributing you agree that your contribution is subject to `LICENSE`.
External contributions are not accepted during the evaluation period without a
signed contributor agreement.
