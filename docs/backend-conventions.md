# HISPANSHIELD — Backend engineering conventions

This document is binding for all domain builders. Read it together with
`.factory/ARCHITECTURE.md`, `backend/app/models/`, `backend/app/core/` and
`backend/app/services/`.

## 1. Stack and runtime

- Python 3.12, FastAPI, SQLAlchemy 2.0 **sync**, PostgreSQL 18, Pydantic v2.
- Virtualenv: `/tmp/opencode/hs-venv/bin/python` (this workstation filesystem
  cannot host symlinked venvs). Ruff: `/tmp/opencode/hs-venv/bin/ruff`.
- Run from `backend/`. `PYTHONPATH=.` is implied by pytest config.
- Do **not** use `Base.metadata.create_all`; schema evolves only through Alembic.

## 2. Domain module layout

Each domain owns a package:

```text
app/modules/<domain>/
├── __init__.py
├── router.py      # APIRouter(prefix="/...", tags=[...])
├── schemas.py     # Pydantic v2 contracts (StrictModel inputs, ORMModel outputs)
├── service.py     # business logic, pure/DB helpers
└── ...            # domain-specific modules (engine.py, builtin_rules.py, seed.py)
```

`app/api/router.py` auto-discovers every package that exposes `router.py:router`.
Never edit it. Never edit `app/main.py`, `app/core/**`, `app/models/**`,
`migrations/**`, `tests/conftest.py`, or another team's module.

## 3. Authentication, tenancy and authorization

```python
from app.core.deps import RequestContext, get_context, require_permission

@router.get("/items")
def list_items(ctx: RequestContext = Depends(require_permission("asset:read"))):
    ...
```

- `ctx.org` is the active organization. **Every** query on tenant data must
  filter by `ctx.org.id` (or include global rows explicitly: `org_id == ... or
  org_id IS NULL`). Never accept an `org_id` parameter for tenant data.
- Cross-tenant access returns **404**, never 403, and never reveals existence.
- Mutations call `ctx.audit(action="asset.create", resource_type="asset",
  resource_id=..., payload={...})` **before** `ctx.db.commit()`.
- The actor is `ctx.user` / `ctx.actor_id` / `ctx.actor_email`; agents and workers
  use `append_audit(...)` directly with `actor_type="system"`.
- Permission keys: see `app/core/rbac.py`. Use existing keys; if a genuinely new
  permission is required, report it — do not add it yourself.

## 4. API contracts

- Base path is `/api/v1`; routers use their own prefix (e.g. `/assets`).
- Errors are raised via `app.core.errors` (`NotFound`, `Forbidden`, `Conflict`,
  `ValidationFailure`, `PolicyDenied`, `ServiceUnavailable`). Never return raw
  dicts for errors.
- List endpoints use `Page[Item]` from `app.core.schemas` and `paginate(...)`:
  `{ "items": [...], "meta": { total, page, page_size, pages, has_next } }`.
- Query parameters: `page` (≥1), `page_size` (1–200), `q`, plus domain filters.
  Free-text filters use `func.lower(col).like(f"%{q.lower()}%")`.
- IDs are UUIDs serialized as strings; timestamps are timezone-aware UTC ISO8601.
- Sort order must be an allow-list of columns, never a raw SQL fragment.
- Input validation: `StrictModel` (extra="forbid"), length/pattern constraints.
  Reject unknown fields with 422 automatically.
- Bulk imports are bounded (≤500 rows) and idempotent where a natural key exists.
- Never return secrets, password hashes, connector credentials or raw tokens.
  Redact before audit with `app.core.audit.redact`.

## 5. Persistence

- Use `db: Session = Depends(get_db)` (or `ctx.db`). Commit explicitly at the end
  of a successful mutation, then `db.refresh(obj)` when needed.
- JSONB columns: use `Mapped[dict]` / `Mapped[list]`; store plain JSON values.
- Use `utcnow()` from `app.core.db` for timestamps.
- For human references and sequences use a per-org advisory lock
  (`SELECT pg_advisory_xact_lock(hashtext(:key))`) plus `MAX(...)`; avoid races.
- Deletes of tenant data must not orphan other tenants. Prefer cascade or
  explicit dependent cleanup, and audit the deletion.
- Store files only under `settings`-derived data directories, sanitize names,
  enforce size limits, and compute SHA-256.

## 6. Background work

- No Celery/Redis/Temporal in this deployment. Workers are idempotent functions
  invoked by small scripts under `scripts/` and/or explicit API endpoints.
- Any queued work must persist its state in PostgreSQL (outbox/queue table or
  domain rows) so a restart can resume. Never rely on in-memory queues for
  durable workflows.
- Long-running external calls must have timeouts, bounded retries (reads only),
  and a circuit breaker (`app.services.connectors.runtime.circuit_breaker`).

## 7. Security invariants

- Outbound URLs from user/connector input go through
  `app.core.ssrf.validate_outbound_url` (HTTP client helper already does this).
- Connector secrets are stored only via `encrypt_secret`; never log them.
- No `eval`, `exec`, `pickle`, shell=True, or dynamic SQL from user input.
- HTML generated for reports must be escaped (`markupsafe.escape`) — no raw user
  content in templates.
- Prompt/tool outputs are untrusted: validate schemas, cap sizes, strip control
  characters, never interpret them as instructions.
- Destructive/state-changing external actions only through
  `app.services.broker.execute_action` after policy evaluation. Read-only
  connector invocations may call adapters directly.
- OT/IoT: passive monitoring by default. No active scanning of OT, no writes to
  controllers, no firmware changes. Deny with a clear policy reason.

## 8. Tests

- Tests live in `backend/tests/{unit,integration,security}/`.
- Reuse fixtures from `tests/conftest.py`: `db`, `client`, `seeded`,
  `auth_client`, `login(...)`, `org_id`. `auth_client` is authenticated as the
  platform admin; for role tests create a user + membership and call `login`.
- Each builder has a dedicated database to avoid parallel-suite interference:
  set `HS_DATABASE_URL` explicitly when running tests, e.g.

```bash
cd backend
HS_DATABASE_URL="postgresql+psycopg://hispanshield@localhost:55432/hs_test_b1" \
  /tmp/opencode/hs-venv/bin/python -m pytest tests/integration/test_assets.py -q
```

- Use local `http.server`/`socketserver` fixtures for connector protocol tests;
  never call the public internet in tests.
- Cover: happy path, validation, cross-tenant isolation (404), RBAC denial (403),
  and domain-specific security invariants.
- Run `ruff format` and `ruff check` on your files; the whole app must stay clean.

## 9. Suggested building blocks

- `app.core.audit.append_audit`, `verify_audit_chain`, `redact`
- `app.core.crypto`: hashing, encryption, token helpers, HMAC
- `app.core.schemas`: `StrictModel`, `ORMModel`, `Page`, `paginate`, password policy
- `app.core.errors`: typed errors
- `app.core.ssrf`: outbound URL validation
- `app.services.actions` + `policy_engine` + `broker`: defensive action governance
- `app.services.connectors.base`: adapter contract, registry, run recorder
- `app.services.connectors.http`: SSRF-safe HTTP with retries
- `app.services.connectors.runtime`: secret decryption, adapter instantiation,
  connector selection, circuit breaker
- `app.services.risk`: vulnerability/asset prioritisation (owner: assets team)

## 10. Definition of done for each domain

1. All declared endpoints implemented with real persistence — no mocks.
2. Every mutation audited; every read tenant-scoped.
3. Pydantic schemas with strict validation; pagination and filters.
4. Tests pass on the assigned database; ruff clean.
5. Docstrings for security-sensitive decisions; no placeholders/TODOs.
6. Report: files, endpoints, tests run, results, open integration notes.
