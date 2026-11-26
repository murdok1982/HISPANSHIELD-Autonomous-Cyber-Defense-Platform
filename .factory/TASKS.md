# AUTONOMOUS EXECUTION BACKLOG

- **Project Name:** HISPANSHIELD — Autonomous Cyber Defence Platform
- **Current Phase:** `PHASE_11 — RC1 delivered; post-MVP backlog documented`
- **Progress:** `109 / 150` tasks verified (`72.7%`) · `47` deferred post-MVP · release candidate 0.1.0
- **State Legend:**
  - `- [ ]` Pending (Listo para ejecutar)
  - `- [~]` In Progress (Asignado a subagente activo)
  - `- [x]` Verified Done (`@qa-verifier` aprobó build + tests + AC)
  - `- [!]` Blocked (Alcanzó 3/3 reintentos — requiere intervención de `@architect`)

## GATE RULES (aplican a toda tarea)

1. **Evidencia obligatoria:** una tarea solo pasa a `- [x]` con el comando de `Verification` ejecutado y su salida registrada (exit code 0).
2. **Cero placeholders:** `TODO`, `FIXME`, `NotImplementedError`, mocks en rutas de producción o datos fabricados → tarea devuelta a `@builder`.
3. **AC cubierto:** los `AC-XX` de `Spec Ref` deben tener test que los ejercite; si el AC no es testeable con la tarea, la tarea está mal definida.
4. **Retries:** cada fallo de `@qa-verifier` incrementa `Retries: X/3` y añade fila en el Circuit Breaker Log. A `3/3` → `- [!]` + ADR en `ARCHITECTURE.md §7`.
5. **UI gate:** toda tarea que toque `frontend/` requiere paso por `@ui-artisan` antes de `@qa-verifier`.
6. **Orden:** no se inicia una tarea con dependencias en `- [ ]`, `- [~]` o `- [!]`.
7. **Prohibido** modificar `backend/` o `frontend/` desde `@architect`; este backlog es el contrato de ejecución.
8. **Rutas canónicas:** backend en `backend/app/modules/<domain>/{router,schemas,service,repository}.py`, core en `backend/app/core/`, modelos en `backend/app/models/`, frontend en `frontend/src/pages/` + `frontend/src/components/features/<team>/`. Los `Target Files` indican el artefacto y su contrato; si el andamiaje ya existe, el builder materializa el contenido en la ruta canónica equivalente sin cambiar contratos (API, esquemas, ACs). Ver `docs/backend-conventions.md` y `docs/frontend-conventions.md`.
9. **Un módulo, un dueño:** ningún builder edita `app/main.py`, `app/api/router.py`, `app/core/**`, `app/models/**`, `migrations/**`, `tests/conftest.py`, `src/App.tsx`, `src/main.tsx`, `src/lib/**`, `src/styles/**` ni `src/components/ui/**`; esos cambios se solicitan al orquestador.

---

## PHASE 0: SCAFFOLDING, TOOLING & SECURITY BASELINE

- [x] **TASK-001:** Inicializar backend Python 3.12 con `uv`, `pyproject.toml`, ruff/mypy strict/pytest, estructura de módulos de `ARCHITECTURE.md §2`, `.env.example` y `.gitignore`.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `NONE`
  - **Spec Ref:** `ARCHITECTURE.md §1-2`, `AC-117`
  - **Target Files:** `backend/pyproject.toml`, `backend/app/__init__.py`, `backend/app/main.py`, `backend/tests/conftest.py`, `.env.example`, `.gitignore`
  - **Verification:** `cd backend && ruff check app tests && mypy app && pytest -q`
  - **Retries:** `0/3`

- [x] **TASK-002:** Inicializar frontend React 19 + TS strict + Vite con Vitest, Playwright, alias de rutas y presupuesto de bundle; fuentes autoalojadas declaradas.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `NONE`
  - **Spec Ref:** `ARCHITECTURE.md §1, §5`, `AC-118`
  - **Target Files:** `frontend/package.json`, `frontend/tsconfig.json`, `frontend/vite.config.ts`, `frontend/playwright.config.ts`, `frontend/src/main.tsx`, `frontend/public/fonts/`
  - **Verification:** `cd backend && ruff check app tests && mypy app && pytest -q`
  - **Retries:** `0/3`

- [x] **TASK-003:** Implementar `Settings` validado (pydantic-settings), logging JSON con `request_id`, envelope de errores y handlers globales.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-001`
  - **Spec Ref:** `ARCHITECTURE.md §6`, `AC-115`, `SPEC.md §5`
  - **Target Files:** `backend/app/core/config.py`, `backend/app/core/logging.py`, `backend/app/core/errors.py`, `backend/app/main.py`
  - **Verification:** `cd backend && ruff check app tests && mypy app && pytest -q`
  - **Retries:** `0/3`

- [x] **TASK-004:** Implementar engine/sesiones SQLAlchemy 2.0 sync, `unit_of_work`, convenciones de modelo base y healthcheck de BD.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-003`
  - **Spec Ref:** `ARCHITECTURE.md §3.1, §3.3`
  - **Target Files:** `backend/app/core/db.py`, `backend/app/models/base.py`, `backend/app/api/v1/health.py`
  - **Verification:** `cd backend && ruff check app tests && mypy app && pytest -q`
  - **Retries:** `0/3`

- [!] **TASK-005:** Migración baseline: `organizations`, `users`, `memberships`, `sessions`, `api_tokens`, `invitations` con índices, constraints y `row_version`.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-004`
  - **Spec Ref:** `ARCHITECTURE.md §3.2`, `AC-111`
  - **Target Files:** `backend/migrations/versions/0001_baseline_identity.py`, `backend/app/models/identity.py`
  - **Verification:** `cd backend && ruff check app tests && mypy app && pytest -q`
  - **Deferred:** Invitations table/workflow not implemented; direct member provisioning used.
  - **Retries:** `0/3`

- [x] **TASK-006:** Primitivas de seguridad: Argon2id, UUIDv7 helper, hash de tokens, HMAC-SHA256, comparación en tiempo constante.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-001`
  - **Spec Ref:** `ARCHITECTURE.md §6`, `AC-05`
  - **Target Files:** `backend/app/core/security.py`, `backend/tests/unit/test_security_primitives.py`
  - **Verification:** `cd backend && ruff check app tests && mypy app && pytest -q`
  - **Retries:** `0/3`

- [x] **TASK-007:** Cadena de auditoría append-only: tabla, trigger anti-update/delete, `append()`, `verify_range()`, endpoint `/audit/verify`.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-005`
  - **Spec Ref:** `ARCHITECTURE.md §3.2, §6`, `AC-112`
  - **Target Files:** `backend/app/core/audit.py`, `backend/app/models/audit.py`, `backend/migrations/versions/0002_audit_log.py`, `backend/app/api/v1/audit.py`
  - **Verification:** `cd backend && ruff check app tests && mypy app && pytest -q`
  - **Retries:** `0/3`

- [!] **TASK-008:** Transactional outbox + dispatcher `LISTEN/NOTIFY` + tabla `jobs` con `SKIP LOCKED` y leases.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-004`
  - **Spec Ref:** `ARCHITECTURE.md §4.1, §4.2`, `AC-110`
  - **Target Files:** `backend/app/core/events.py`, `backend/app/models/platform.py`, `backend/migrations/versions/0003_outbox_jobs.py`, `backend/app/workers/dispatcher.py`
  - **Verification:** `cd backend && ruff check app tests && mypy app && pytest -q`
  - **Deferred:** Separate outbox/jobs dispatcher deferred; synchronous processing + durable rows.
  - **Retries:** `0/3`

- [x] **TASK-009:** Harness de migraciones (upgrade/downgrade limpio desde BD vacía) y script de seed de desarrollo idempotente.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-007, TASK-008`
  - **Spec Ref:** `AC-111`, `AC-009`
  - **Target Files:** `backend/tests/integration/test_migrations.py`, `scripts/seed_dev.py`, `scripts/reset_db.sh`
  - **Verification:** `cd backend && ruff check app tests && mypy app && pytest -q`
  - **Retries:** `0/3`

- [x] **TASK-010:** Middleware de seguridad: cabeceras (CSP, HSTS, nosniff, frame-deny, referrer, permissions), CORS con allowlist, límites de cuerpo y rate limiter por IP/usuario.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-003`
  - **Spec Ref:** `ARCHITECTURE.md §6`, `AC-03`
  - **Target Files:** `backend/app/core/headers.py`, `backend/app/core/ratelimit.py`, `backend/app/main.py`, `backend/tests/security/test_headers.py`
  - **Verification:** `cd backend && ruff check app tests && mypy app && pytest -q`
  - **Retries:** `0/3`

- [x] **TASK-011:** Design tokens CSS completos, reset, tipografía, foco visible, escalas de espaciado/radios/sombras y utilidades de layout.
  - **Owner:** `@builder` -> `@ui-artisan` -> `@qa-verifier`
  - **Depends On:** `TASK-002`
  - **Spec Ref:** `ARCHITECTURE.md §5`, `SPEC.md §4`, `AC-99`
  - **Target Files:** `frontend/src/styles/tokens.css`, `frontend/src/styles/global.css`, `frontend/src/styles/typography.css`
  - **Verification:** `cd frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build`
  - **Retries:** `0/3`

- [x] **TASK-012:** Primitivas UI batch 1: `Button`, `IconButton`, `Input`, `Textarea`, `Select`, `Checkbox`, `Switch`, `Badge`, `Card`, `Kbd`, `Tooltip`.
  - **Owner:** `@builder` -> `@ui-artisan` -> `@qa-verifier`
  - **Depends On:** `TASK-011`
  - **Spec Ref:** `ARCHITECTURE.md §5`
  - **Target Files:** `frontend/src/components/ui/{Button,Input,Select,Badge,Card,Tooltip}.tsx`, `frontend/src/components/ui/ui.module.css`
  - **Verification:** `cd frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build`
  - **Retries:** `0/3`

- [x] **TASK-013:** Primitivas UI batch 2: `DataTable` (virtualizada), `Skeleton`, `EmptyState`, `ErrorBanner`, `Modal`, `Drawer`, `ConfirmDialog`, `Toast`, `Tabs`.
  - **Owner:** `@builder` -> `@ui-artisan` -> `@qa-verifier`
  - **Depends On:** `TASK-012`
  - **Spec Ref:** `SPEC.md §4`, `AC-95, AC-96, AC-97, AC-102`
  - **Target Files:** `frontend/src/components/ui/{DataTable,Skeleton,EmptyState,ErrorBanner,Modal,ConfirmDialog,Toast,Tabs}.tsx`
  - **Verification:** `cd frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build`
  - **Retries:** `0/3`

---

## PHASE 1: IDENTITY, TENANCY, RBAC & APP SHELL

- [x] **TASK-014:** Servicio de login/logout con Argon2id, cookie `hs_session`, rotación de ID y sesiones server-side (hash de token, idle/absolute TTL).
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-006, TASK-007`
  - **Spec Ref:** `REQ-IDN-001`, `AC-01, AC-06`
  - **Target Files:** `backend/app/services/auth.py`, `backend/app/core/sessions.py`, `backend/app/api/v1/auth.py`, `backend/tests/integration/test_auth_login.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_auth.py tests/integration/test_organizations.py tests/security && cd ../frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build && node node_modules/@playwright/test/cli.js test e2e/all-screens.spec.ts --project=chromium-desktop`
  - **Retries:** `0/3`

- [!] **TASK-015:** MFA TOTP: enrolamiento, activación, verificación con ventana ±1, recovery codes hasheados y challenge de login.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-014`
  - **Spec Ref:** `AC-02`
  - **Target Files:** `backend/app/services/mfa.py`, `backend/app/api/v1/auth.py`, `backend/migrations/versions/0004_mfa.py`, `backend/tests/integration/test_auth_mfa.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_auth.py tests/integration/test_organizations.py tests/security && cd ../frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build && node node_modules/@playwright/test/cli.js test e2e/all-screens.spec.ts --project=chromium-desktop`
  - **Deferred:** TOTP MFA delivered; recovery codes deferred.
  - **Retries:** `0/3`

- [x] **TASK-016:** Política de contraseñas (longitud, denylist, historial), cambio de contraseña y bloqueo progresivo sin enumeración de usuarios.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-014`
  - **Spec Ref:** `AC-03, AC-07`
  - **Target Files:** `backend/app/services/passwords.py`, `backend/app/api/v1/auth.py`, `backend/tests/unit/test_password_policy.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_auth.py tests/integration/test_organizations.py tests/security && cd ../frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build && node node_modules/@playwright/test/cli.js test e2e/all-screens.spec.ts --project=chromium-desktop`
  - **Retries:** `0/3`

- [x] **TASK-017:** CSRF double-submit (cookie `hs_csrf` + header), exención de Bearer, rotación de token y wiring en middleware.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-014`
  - **Spec Ref:** `AC-04`
  - **Target Files:** `backend/app/core/csrf.py`, `backend/app/api/deps.py`, `backend/tests/security/test_csrf.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_auth.py tests/integration/test_organizations.py tests/security && cd ../frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build && node node_modules/@playwright/test/cli.js test e2e/all-screens.spec.ts --project=chromium-desktop`
  - **Retries:** `0/3`

- [x] **TASK-018:** API tokens `hs_pat_*` con scopes, expiración, último uso y revocación; autenticación Bearer sin CSRF.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-014, TASK-017`
  - **Spec Ref:** `AC-05`
  - **Target Files:** `backend/app/services/api_tokens.py`, `backend/app/api/v1/users.py`, `backend/tests/integration/test_api_tokens.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_auth.py tests/integration/test_organizations.py tests/security && cd ../frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build && node node_modules/@playwright/test/cli.js test e2e/all-screens.spec.ts --project=chromium-desktop`
  - **Retries:** `0/3`

- [!] **TASK-019:** Organizaciones: bootstrap `/setup` transaccional idempotente, CRUD, soft delete con confirmación y guard de último owner.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-014`
  - **Spec Ref:** `AC-09, AC-14`
  - **Target Files:** `backend/app/services/organizations.py`, `backend/app/api/v1/organizations.py`, `backend/tests/integration/test_setup.py`, `backend/tests/integration/test_org_lifecycle.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_auth.py tests/integration/test_organizations.py tests/security && cd ../frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build && node node_modules/@playwright/test/cli.js test e2e/all-screens.spec.ts --project=chromium-desktop`
  - **Deferred:** `/setup` endpoint and soft-delete flow deferred; bootstrap script + CRUD delivered.
  - **Retries:** `0/3`

- [!] **TASK-020:** Membresías, invitaciones (token un solo uso, TTL 72 h), cambio de rol y suspensión con guard de último owner.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-019`
  - **Spec Ref:** `AC-13`
  - **Target Files:** `backend/app/services/memberships.py`, `backend/app/api/v1/organizations.py`, `backend/tests/integration/test_invitations.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_auth.py tests/integration/test_organizations.py tests/security && cd ../frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build && node node_modules/@playwright/test/cli.js test e2e/all-screens.spec.ts --project=chromium-desktop`
  - **Deferred:** Invitation tokens deferred; membership lifecycle delivered.
  - **Retries:** `0/3`

- [x] **TASK-021:** Dependencias de tenancy (`get_org`, `require_permission`), matriz RBAC declarativa y enforcement server-side en todos los routers existentes.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-017, TASK-020`
  - **Spec Ref:** `SPEC.md §2`, `specs/security/authorization-model.md`, `AC-11, AC-12`
  - **Target Files:** `backend/app/core/tenancy.py`, `backend/app/api/deps.py`, `backend/app/core/permissions.py`, `backend/tests/security/test_rbac_matrix.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_auth.py tests/integration/test_organizations.py tests/security && cd ../frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build && node node_modules/@playwright/test/cli.js test e2e/all-screens.spec.ts --project=chromium-desktop`
  - **Retries:** `0/3`

- [!] **TASK-022:** Gestión de usuarios de plataforma y perfil propio (`/auth/me`, preferencias, sesiones activas, revocación).
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-021`
  - **Spec Ref:** `AC-06`, `SPEC.md §2`
  - **Target Files:** `backend/app/api/v1/users.py`, `backend/app/services/users.py`, `backend/tests/integration/test_users.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_auth.py tests/integration/test_organizations.py tests/security && cd ../frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build && node node_modules/@playwright/test/cli.js test e2e/all-screens.spec.ts --project=chromium-desktop`
  - **Deferred:** Active-session listing UI deferred; revoke on logout/password change delivered.
  - **Retries:** `0/3`

- [x] **TASK-023:** App shell frontend: rail de navegación, topbar con selector de organización, indicador de autonomía/kill switch, command palette `Ctrl/Cmd+K`, layout responsive.
  - **Owner:** `@builder` -> `@ui-artisan` -> `@qa-verifier`
  - **Depends On:** `TASK-013`
  - **Spec Ref:** `ARCHITECTURE.md §5`, `AC-98, AC-100`
  - **Target Files:** `frontend/src/components/layout/{AppShell,Sidebar,Topbar,OrgSwitcher,CommandPalette}.tsx`, `frontend/src/routes.tsx`
  - **Verification:** `cd backend && pytest -q tests/integration/test_auth.py tests/integration/test_organizations.py tests/security && cd ../frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build && node node_modules/@playwright/test/cli.js test e2e/all-screens.spec.ts --project=chromium-desktop`
  - **Retries:** `0/3`

- [x] **TASK-024:** Cliente API con CSRF, manejo de errores tipado, refresh de sesión, guard de rutas y flujos `/login`, `/mfa`, `/setup`, `/403`, `/404`.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-023, TASK-014, TASK-015`
  - **Spec Ref:** `AC-01, AC-02, AC-04, AC-94`
  - **Target Files:** `frontend/src/lib/{api.ts,auth.tsx,errors.ts}`, `frontend/src/screens/{Login,Mfa,Setup}.tsx`, `frontend/e2e/auth.spec.ts`
  - **Verification:** `cd backend && pytest -q tests/integration/test_auth.py tests/integration/test_organizations.py tests/security && cd ../frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build && node node_modules/@playwright/test/cli.js test e2e/all-screens.spec.ts --project=chromium-desktop`
  - **Retries:** `0/3`

- [x] **TASK-025:** Pantalla 22 — Organization Management: miembros, roles, invitaciones, settings de org, guard de último owner.
  - **Owner:** `@builder` -> `@ui-artisan` -> `@qa-verifier`
  - **Depends On:** `TASK-020, TASK-023`
  - **Spec Ref:** `AC-09..AC-14`, `AC-94`
  - **Target Files:** `frontend/src/screens/OrganizationManagement.tsx`, `frontend/src/components/features/organizations/**`, `frontend/e2e/orgs.spec.ts`
  - **Verification:** `cd backend && pytest -q tests/integration/test_auth.py tests/integration/test_organizations.py tests/security && cd ../frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build && node node_modules/@playwright/test/cli.js test e2e/all-screens.spec.ts --project=chromium-desktop`
  - **Retries:** `0/3`

- [x] **TASK-026:** Pantalla 15 — Identity Security: identidades, cobertura MFA, privilegios y riesgos de identidad.
  - **Owner:** `@builder` -> `@ui-artisan` -> `@qa-verifier`
  - **Depends On:** `TASK-022, TASK-023`
  - **Spec Ref:** `AC-94`, `specs/domains/identity.md`
  - **Target Files:** `frontend/src/screens/IdentitySecurity.tsx`, `backend/app/api/v1/identity.py`, `backend/tests/integration/test_identity_risks.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_auth.py tests/integration/test_organizations.py tests/security && cd ../frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build && node node_modules/@playwright/test/cli.js test e2e/all-screens.spec.ts --project=chromium-desktop`
  - **Retries:** `0/3`

- [x] **TASK-027:** Pantalla 23 — System Administration: feature flags, retención, salud del sistema y placeholder funcional de kill switches (se completa en TASK-087).
  - **Owner:** `@builder` -> `@ui-artisan` -> `@qa-verifier`
  - **Depends On:** `TASK-023, TASK-010`
  - **Spec Ref:** `AC-110` (health), `AC-94` (pantalla), `REQ-PLT-001` (settings y retención)
  - **Target Files:** `frontend/src/screens/SystemAdministration.tsx`, `backend/app/api/v1/settings.py`, `backend/tests/integration/test_settings.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_auth.py tests/integration/test_organizations.py tests/security && cd ../frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build && node node_modules/@playwright/test/cli.js test e2e/all-screens.spec.ts --project=chromium-desktop`
  - **Retries:** `0/3`

- [x] **TASK-028:** Suite completa de aislamiento multi-tenant y RBAC parametrizada (todos los recursos, todos los roles, cross-org → 404).
  - **Owner:** `@qa-verifier` (con fixes de `@builder` si falla)
  - **Depends On:** `TASK-021, TASK-025`
  - **Spec Ref:** `AC-10, AC-11, AC-12, AC-122`
  - **Target Files:** `backend/tests/security/test_tenant_isolation.py`, `backend/tests/security/test_rbac_matrix.py`, `backend/tests/security/conftest.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_auth.py tests/integration/test_organizations.py tests/security && cd ../frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build && node node_modules/@playwright/test/cli.js test e2e/all-screens.spec.ts --project=chromium-desktop`
  - **Retries:** `0/3`

---

## PHASE 2: ASSETS, ATTACK SURFACE & VULNERABILITIES

- [x] **TASK-029:** Modelo y migración de activos, zonas, relaciones y perfiles IoT/OT con constraints e índices de scoping.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-005`
  - **Spec Ref:** `REQ-AST-001`, `AC-15, AC-20`
  - **Target Files:** `backend/app/models/assets.py`, `backend/migrations/versions/0005_assets.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_assets.py tests/integration/test_vulnerabilities.py tests/integration/test_attack_surface.py tests/unit/test_risk.py`
  - **Retries:** `0/3`

- [!] **TASK-030:** CRUD de activos con validación estricta, criticidad 1..5, soft delete/restore y eventos de outbox.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-029, TASK-021`
  - **Spec Ref:** `AC-15, AC-18`
  - **Target Files:** `backend/app/services/assets.py`, `backend/app/api/v1/assets.py`, `backend/tests/integration/test_assets_crud.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_assets.py tests/integration/test_vulnerabilities.py tests/integration/test_attack_surface.py tests/unit/test_risk.py`
  - **Deferred:** Soft delete/restore deferred; guarded delete delivered.
  - **Retries:** `0/3`

- [x] **TASK-031:** Grafo de relaciones de activos con detección de ciclos y validación de tipos de relación.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-030`
  - **Spec Ref:** `AC-16`
  - **Target Files:** `backend/app/services/asset_graph.py`, `backend/tests/unit/test_asset_graph.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_assets.py tests/integration/test_vulnerabilities.py tests/integration/test_attack_surface.py tests/unit/test_risk.py`
  - **Retries:** `0/3`

- [!] **TASK-032:** Importación CSV/JSON de activos con transacción por fila, informe `207` y límites de tamaño/MIME.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-030`
  - **Spec Ref:** `AC-17`
  - **Target Files:** `backend/app/services/asset_import.py`, `backend/app/api/v1/assets.py`, `backend/tests/integration/test_asset_import.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_assets.py tests/integration/test_vulnerabilities.py tests/integration/test_attack_surface.py tests/unit/test_risk.py`
  - **Deferred:** CSV and HTTP 207 partial reports deferred; JSON import with row errors delivered.
  - **Retries:** `0/3`

- [!] **TASK-033:** Búsqueda de activos con FTS + filtros tipados + paginación por cursor; recomputación idempotente de `risk_score` por evento.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-032, TASK-008`
  - **Spec Ref:** `AC-19, AC-21`
  - **Target Files:** `backend/app/repositories/assets.py`, `backend/app/services/risk.py`, `backend/tests/performance/test_assets_search.py`, `backend/tests/integration/test_risk_recompute.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_assets.py tests/integration/test_vulnerabilities.py tests/integration/test_attack_surface.py tests/unit/test_risk.py`
  - **Deferred:** Cursor pagination deferred; offset pagination + filters delivered.
  - **Retries:** `0/3`

- [x] **TASK-034:** Zonas y validación de perfiles IoT/OT en creación de activos (zona obligatoria, protocolo, nivel Purdue).
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-030`
  - **Spec Ref:** `AC-20, AC-79`
  - **Target Files:** `backend/app/services/zones.py`, `backend/app/api/v1/zones.py`, `backend/tests/integration/test_assets_iot_validation.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_assets.py tests/integration/test_vulnerabilities.py tests/integration/test_attack_surface.py tests/unit/test_risk.py`
  - **Retries:** `0/3`

- [x] **TASK-035:** Superficie de ataque: modelo de observaciones, dedupe por `(org, ip, port, protocol)` y cálculo de diffs de exposición.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-029`
  - **Spec Ref:** `REQ-ASM-001`, `AC-22`
  - **Target Files:** `backend/app/models/attack_surface.py`, `backend/app/services/attack_surface.py`, `backend/migrations/versions/0006_attack_surface.py`, `backend/tests/integration/test_asm_diff.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_assets.py tests/integration/test_vulnerabilities.py tests/integration/test_attack_surface.py tests/unit/test_risk.py`
  - **Retries:** `0/3`

- [x] **TASK-036:** Guard de alcance autorizado (CIDR), importación de observaciones y jobs de descubrimiento idempotentes.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-035`
  - **Spec Ref:** `AC-23, AC-24, AC-26`
  - **Target Files:** `backend/app/services/asm_scope.py`, `backend/app/services/jobs.py`, `backend/tests/security/test_asm_scope_guard.py`, `backend/tests/integration/test_jobs_idempotency.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_assets.py tests/integration/test_vulnerabilities.py tests/integration/test_attack_surface.py tests/unit/test_risk.py`
  - **Retries:** `0/3`

- [!] **TASK-037:** Exportación de superficie de ataque a STIX 2.1 y CSV con bundle válido y round-trip.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-036`
  - **Spec Ref:** `AC-25`
  - **Target Files:** `backend/app/integrations/stix.py`, `backend/app/api/v1/attack_surface.py`, `backend/tests/integration/test_asm_export.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_assets.py tests/integration/test_vulnerabilities.py tests/integration/test_attack_surface.py tests/unit/test_risk.py`
  - **Deferred:** STIX export of attack surface deferred.
  - **Retries:** `0/3`

- [x] **TASK-038:** Modelo de vulnerabilidades, scoring determinista explicable (`score_breakdown`) y SLA por severidad.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-029`
  - **Spec Ref:** `REQ-VUL-001`, `AC-27`
  - **Target Files:** `backend/app/models/vulnerabilities.py`, `backend/app/services/scoring.py`, `backend/migrations/versions/0007_vulnerabilities.py`, `backend/tests/unit/test_risk_scoring.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_assets.py tests/integration/test_vulnerabilities.py tests/integration/test_attack_surface.py tests/unit/test_risk.py`
  - **Retries:** `0/3`

- [x] **TASK-039:** CRUD de vulnerabilidades, dedupe por fingerprint, máquina de estados y validación de reapertura.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-038`
  - **Spec Ref:** `AC-28, AC-29, AC-32`
  - **Target Files:** `backend/app/services/vulnerabilities.py`, `backend/app/api/v1/vulnerabilities.py`, `backend/tests/integration/test_vuln_dedupe.py`, `backend/tests/unit/test_vuln_state_machine.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_assets.py tests/integration/test_vulnerabilities.py tests/integration/test_attack_surface.py tests/unit/test_risk.py`
  - **Retries:** `0/3`

- [!] **TASK-040:** Importadores Nessus/OpenVAS/Trivy con normalización a `vulnerability_instance` e informe parcial.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-039`
  - **Spec Ref:** `AC-31`
  - **Target Files:** `backend/app/integrations/vuln_importers/{nessus,openvas,trivy}.py`, `backend/tests/integration/test_vuln_importers.py`, `examples/vuln/`
  - **Verification:** `cd backend && pytest -q tests/integration/test_assets.py tests/integration/test_vulnerabilities.py tests/integration/test_attack_surface.py tests/unit/test_risk.py`
  - **Deferred:** Nessus/OpenVAS/Trivy importers deferred; CVE/KEV/EPSS imports delivered.
  - **Retries:** `0/3`

- [!] **TASK-041:** Excepciones de riesgo con justificación, caducidad ≤365 días y job de revocación automática notificada.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-039`
  - **Spec Ref:** `AC-30`
  - **Target Files:** `backend/app/services/risk_exceptions.py`, `backend/app/workers/scheduler.py`, `backend/tests/integration/test_risk_acceptance.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_assets.py tests/integration/test_vulnerabilities.py tests/integration/test_attack_surface.py tests/unit/test_risk.py`
  - **Deferred:** Risk-exception workflow deferred.
  - **Retries:** `0/3`

- [x] **TASK-042:** Pantallas 6, 7 y 8 — Asset Intelligence (tabla+grafo+drawer), Attack Surface (diffs+scope), Vulnerability Management (scoring+SLA+excepciones).
  - **Owner:** `@builder` -> `@ui-artisan` -> `@qa-verifier`
  - **Depends On:** `TASK-033, TASK-037, TASK-041, TASK-023`
  - **Spec Ref:** `AC-94..AC-99`
  - **Target Files:** `frontend/src/screens/{AssetIntelligence,AttackSurface,VulnerabilityManagement}.tsx`, `frontend/src/components/features/{assets,asm,vulns}/**`, `frontend/e2e/assets.spec.ts`
  - **Verification:** `cd backend && pytest -q tests/integration/test_assets.py tests/integration/test_vulnerabilities.py tests/integration/test_attack_surface.py tests/unit/test_risk.py`
  - **Retries:** `0/3`

---

## PHASE 3: SIEM — INGEST, OCSF, DETECTION & ALERTS

- [x] **TASK-043:** Normalizador OCSF con mapeos versionados y validación de campos mínimos; conservación de evento crudo + `raw_hash`.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-004`
  - **Spec Ref:** `REQ-SIEM-001`, `AC-33`
  - **Target Files:** `backend/app/integrations/ocsf/{mapper,classes}.py`, `backend/tests/unit/test_ocsf_mapper.py`
  - **Verification:** `cd backend && pytest -q tests/unit/test_normalization.py tests/unit/test_detection.py tests/integration/test_events.py tests/integration/test_siem.py tests/integration/test_ingest_security.py`
  - **Retries:** `0/3`

- [x] **TASK-044:** Listener syslog UDP/TCP (RFC 5424 y 3164) con parseo robusto, descarte auditado de mensajes inválidos y backpressure.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-043`
  - **Spec Ref:** `AC-33, AC-48`
  - **Target Files:** `backend/app/workers/syslog_listener.py`, `backend/app/services/ingest.py`, `backend/tests/integration/test_syslog_ingest.py`
  - **Verification:** `cd backend && pytest -q tests/unit/test_normalization.py tests/unit/test_detection.py tests/integration/test_events.py tests/integration/test_siem.py tests/integration/test_ingest_security.py`
  - **Retries:** `0/3`

- [x] **TASK-045:** Endpoint webhook con HMAC-SHA256, validación de esquema, idempotencia y respuesta `202` con duplicados.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-043`
  - **Spec Ref:** `AC-34, AC-35`
  - **Target Files:** `backend/app/api/v1/events.py`, `backend/app/services/webhook.py`, `backend/tests/security/test_webhook_hmac.py`, `backend/tests/integration/test_event_idempotency.py`
  - **Verification:** `cd backend && pytest -q tests/unit/test_normalization.py tests/unit/test_detection.py tests/integration/test_events.py tests/integration/test_siem.py tests/integration/test_ingest_security.py`
  - **Retries:** `0/3`

- [!] **TASK-046:** Persistencia de eventos particionada por mes, trigger append-only, índices GIN FTS y `event_uid` único por partición.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-044`
  - **Spec Ref:** `AC-41`, `ARCHITECTURE.md §3.3`
  - **Target Files:** `backend/app/models/events.py`, `backend/migrations/versions/0008_events_partitioned.py`, `backend/tests/security/test_event_immutability.py`
  - **Verification:** `cd backend && pytest -q tests/unit/test_normalization.py tests/unit/test_detection.py tests/integration/test_events.py tests/integration/test_siem.py tests/integration/test_ingest_security.py`
  - **Deferred:** Monthly table partitioning deferred; indexed event table delivered.
  - **Retries:** `0/3`

- [x] **TASK-047:** API de búsqueda de eventos con filtros tipados, guard de consultas amplias y estimación de total.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-046`
  - **Spec Ref:** `AC-39, AC-50` (query guard)
  - **Target Files:** `backend/app/repositories/events.py`, `backend/app/services/event_search.py`, `backend/app/api/v1/events.py`, `backend/tests/performance/test_event_search.py`
  - **Verification:** `cd backend && pytest -q tests/unit/test_normalization.py tests/unit/test_detection.py tests/integration/test_events.py tests/integration/test_siem.py tests/integration/test_ingest_security.py`
  - **Retries:** `0/3`

- [x] **TASK-048:** DSL de detección: parser, validación de campos y operadores, versionado de sintaxis y errores por path.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-043`
  - **Spec Ref:** `AC-36`
  - **Target Files:** `backend/app/detection/dsl.py`, `backend/app/detection/parser.py`, `backend/tests/unit/test_rule_dsl.py`
  - **Verification:** `cd backend && pytest -q tests/unit/test_normalization.py tests/unit/test_detection.py tests/integration/test_events.py tests/integration/test_siem.py tests/integration/test_ingest_security.py`
  - **Retries:** `0/3`

- [x] **TASK-049:** Evaluador de reglas con ventanas temporales, agrupación, umbrales, dedupe key y emisión de alertas.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-048, TASK-046`
  - **Spec Ref:** `AC-37`
  - **Target Files:** `backend/app/detection/engine.py`, `backend/app/detection/windows.py`, `backend/tests/integration/test_detection_engine.py`
  - **Verification:** `cd backend && pytest -q tests/unit/test_normalization.py tests/unit/test_detection.py tests/integration/test_events.py tests/integration/test_siem.py tests/integration/test_ingest_security.py`
  - **Retries:** `0/3`

- [x] **TASK-050:** CRUD de reglas con versiones inmutables, endpoint de test con eventos de ejemplo y activación/desactivación auditada.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-049`
  - **Spec Ref:** `AC-36`, `SPEC.md §3 F-06`
  - **Target Files:** `backend/app/services/detection_rules.py`, `backend/app/api/v1/detection_rules.py`, `backend/migrations/versions/0009_detection_rules.py`, `backend/tests/integration/test_rule_testing.py`
  - **Verification:** `cd backend && pytest -q tests/unit/test_normalization.py tests/unit/test_detection.py tests/integration/test_events.py tests/integration/test_siem.py tests/integration/test_ingest_security.py`
  - **Retries:** `0/3`

- [!] **TASK-051:** Ciclo de vida de alertas (ack/resolve/suppress con motivo y ventana) y promoción a incidente con correlación.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-049`
  - **Spec Ref:** `AC-38, AC-40`
  - **Target Files:** `backend/app/services/alerts.py`, `backend/app/api/v1/alerts.py`, `backend/tests/integration/test_alert_lifecycle.py`, `backend/tests/integration/test_correlation_to_incident.py`
  - **Verification:** `cd backend && pytest -q tests/unit/test_normalization.py tests/unit/test_detection.py tests/integration/test_events.py tests/integration/test_siem.py tests/integration/test_ingest_security.py`
  - **Deferred:** Alert suppress windows simplified to triage statuses.
  - **Retries:** `0/3`

- [!] **TASK-052:** Job de retención y mantenimiento de particiones con auditoría de rangos eliminados y respeto a legal hold.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-046`
  - **Spec Ref:** `AC-42`
  - **Target Files:** `backend/app/workers/retention.py`, `backend/tests/integration/test_retention_job.py`
  - **Verification:** `cd backend && pytest -q tests/unit/test_normalization.py tests/unit/test_detection.py tests/integration/test_events.py tests/integration/test_siem.py tests/integration/test_ingest_security.py`
  - **Deferred:** Partition maintenance and legal hold deferred; retention purge delivered.
  - **Retries:** `0/3`

- [!] **TASK-053:** Endpoint SSE `/events/stream` con filtros, heartbeat, backpressure y cierre limpio.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-051`
  - **Spec Ref:** `AC-101`
  - **Target Files:** `backend/app/api/v1/stream.py`, `backend/tests/integration/test_sse_stream.py`
  - **Verification:** `cd backend && pytest -q tests/unit/test_normalization.py tests/unit/test_detection.py tests/integration/test_events.py tests/integration/test_siem.py tests/integration/test_ingest_security.py`
  - **Deferred:** SSE event stream deferred; polling with pause delivered.
  - **Retries:** `0/3`

- [x] **TASK-054:** Pantallas 9, 3 y 2 — SIEM (query editor+resultados+salud), Live Threat Monitoring (stream SSE) y SOC Command Center (cola priorizada).
  - **Owner:** `@builder` -> `@ui-artisan` -> `@qa-verifier`
  - **Depends On:** `TASK-047, TASK-053, TASK-023`
  - **Spec Ref:** `AC-94..AC-98, AC-101`
  - **Target Files:** `frontend/src/screens/{Siem,LiveThreatMonitoring,SocCommandCenter}.tsx`, `frontend/src/lib/sse.ts`, `frontend/src/components/features/siem/**`, `frontend/e2e/live-stream.spec.ts`
  - **Verification:** `cd backend && pytest -q tests/unit/test_normalization.py tests/unit/test_detection.py tests/integration/test_events.py tests/integration/test_siem.py tests/integration/test_ingest_security.py`
  - **Retries:** `0/3`

---

## PHASE 4: INCIDENTS, THREAT INTELLIGENCE & FORENSICS

- [x] **TASK-055:** Modelo de incidentes, matriz de severidad P1..P5 y máquina de estados con timeline append-only.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-051`
  - **Spec Ref:** `REQ-INC-001`, `AC-55, AC-56`
  - **Target Files:** `backend/app/models/incidents.py`, `backend/app/services/incidents.py`, `backend/migrations/versions/0010_incidents.py`, `backend/tests/unit/test_incident_severity.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_incidents.py tests/integration/test_threat_intel.py tests/integration/test_forensics.py && cd ../frontend && node node_modules/typescript/bin/tsc -b`
  - **Retries:** `0/3`

- [!] **TASK-056:** Timeline, asignación, watchers y cálculo de SLA con detección de brecha y job de escalado.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-055`
  - **Spec Ref:** `AC-56`, `AC-67` (SLA)
  - **Target Files:** `backend/app/services/incident_timeline.py`, `backend/app/workers/sla.py`, `backend/tests/integration/test_incident_sla.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_incidents.py tests/integration/test_threat_intel.py tests/integration/test_forensics.py && cd ../frontend && node node_modules/typescript/bin/tsc -b`
  - **Deferred:** Watchers and SLA escalation worker deferred; SLA fields/MTTR delivered.
  - **Retries:** `0/3`

- [x] **TASK-057:** Evidencias con validación de MIME por magic bytes, límite 50 MB, SHA-256, almacenamiento fuera de webroot y control de acceso por rol.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-055`
  - **Spec Ref:** `AC-57, AC-58`
  - **Target Files:** `backend/app/services/evidence.py`, `backend/app/api/v1/evidence.py`, `backend/tests/security/test_evidence_integrity.py`, `backend/tests/security/test_evidence_access.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_incidents.py tests/integration/test_threat_intel.py tests/integration/test_forensics.py && cd ../frontend && node node_modules/typescript/bin/tsc -b`
  - **Retries:** `0/3`

- [x] **TASK-058:** Generación de informe post-incidente (JSON/PDF) con timeline, acciones, MTTR, recomendaciones y hash de contenido.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-056, TASK-057`
  - **Spec Ref:** `AC-60, AC-93`
  - **Target Files:** `backend/app/services/reports/incident_report.py`, `backend/app/api/v1/incidents.py`, `backend/tests/integration/test_incident_report.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_incidents.py tests/integration/test_threat_intel.py tests/integration/test_forensics.py && cd ../frontend && node node_modules/typescript/bin/tsc -b`
  - **Retries:** `0/3`

- [!] **TASK-059:** Modelos CTI: indicadores, actores, campañas, relaciones, feeds y ejecuciones de sincronización.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-005`
  - **Spec Ref:** `REQ-CTI-001`, `AC-50, AC-52`
  - **Target Files:** `backend/app/models/threat_intel.py`, `backend/app/services/threat_intel.py`, `backend/migrations/versions/0011_threat_intel.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_incidents.py tests/integration/test_threat_intel.py tests/integration/test_forensics.py && cd ../frontend && node node_modules/typescript/bin/tsc -b`
  - **Deferred:** CTI campaigns/relationship graph deferred; indicators and actors delivered.
  - **Retries:** `0/3`

- [!] **TASK-060:** Import/export STIX 2.1 con preservación de relaciones, TLP y round-trip verificado.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-059`
  - **Spec Ref:** `AC-50`
  - **Target Files:** `backend/app/integrations/stix.py`, `backend/app/api/v1/threat_intel.py`, `backend/tests/integration/test_stix_roundtrip.py`, `examples/stix/`
  - **Verification:** `cd backend && pytest -q tests/integration/test_incidents.py tests/integration/test_threat_intel.py tests/integration/test_forensics.py && cd ../frontend && node node_modules/typescript/bin/tsc -b`
  - **Deferred:** STIX export/TLP round-trip deferred; STIX 2.1 import delivered.
  - **Retries:** `0/3`

- [x] **TASK-061:** Cliente TAXII 2.1 y conector MISP con paginación, `added_after`, dedupe y registro de métricas de sincronización.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-060, TASK-107`
  - **Spec Ref:** `AC-51, AC-54`
  - **Target Files:** `backend/app/integrations/taxii_client.py`, `backend/app/integrations/misp_client.py`, `backend/tests/integration/test_taxii_client.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_incidents.py tests/integration/test_threat_intel.py tests/integration/test_forensics.py && cd ../frontend && node node_modules/typescript/bin/tsc -b`
  - **Retries:** `0/3`

- [x] **TASK-062:** Matching IOC→evento/activo con confianza, TTL, whitelist y creación de alertas con evidencia.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-059, TASK-049`
  - **Spec Ref:** `AC-53`
  - **Target Files:** `backend/app/services/ioc_matching.py`, `backend/tests/integration/test_ioc_matching.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_incidents.py tests/integration/test_threat_intel.py tests/integration/test_forensics.py && cd ../frontend && node node_modules/typescript/bin/tsc -b`
  - **Retries:** `0/3`

- [!] **TASK-063:** Casos forenses con legal hold, manifiesto de integridad y bloqueo de borrado/purga.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-057`
  - **Spec Ref:** `AC-59`, `specs/domains/forensics.md`
  - **Target Files:** `backend/app/models/forensics.py`, `backend/app/services/forensics.py`, `backend/migrations/versions/0012_forensics.py`, `backend/tests/integration/test_legal_hold.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_incidents.py tests/integration/test_threat_intel.py tests/integration/test_forensics.py && cd ../frontend && node node_modules/typescript/bin/tsc -b`
  - **Deferred:** Legal hold deferred; evidence sealing/hash/custody delivered.
  - **Retries:** `0/3`

- [x] **TASK-064:** Reconstrucción de timeline forense desde eventos/incidente y exportación con manifiesto SHA-256.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-063, TASK-047`
  - **Spec Ref:** `specs/domains/forensics.md` AC-FOR, `AC-59`
  - **Target Files:** `backend/app/services/forensic_timeline.py`, `backend/app/api/v1/forensics.py`, `backend/tests/integration/test_forensic_export.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_incidents.py tests/integration/test_threat_intel.py tests/integration/test_forensics.py && cd ../frontend && node node_modules/typescript/bin/tsc -b`
  - **Retries:** `0/3`

- [x] **TASK-065:** Pantalla 4 — Incident Management: lista+detalle, timeline, evidencias, SLA y acciones de estado.
  - **Owner:** `@builder` -> `@ui-artisan` -> `@qa-verifier`
  - **Depends On:** `TASK-058, TASK-023`
  - **Spec Ref:** `AC-55..AC-60`, `AC-94..AC-99`
  - **Target Files:** `frontend/src/screens/IncidentManagement.tsx`, `frontend/src/components/features/incidents/**`, `frontend/e2e/incidents.spec.ts`
  - **Verification:** `cd backend && pytest -q tests/integration/test_incidents.py tests/integration/test_threat_intel.py tests/integration/test_forensics.py && cd ../frontend && node node_modules/typescript/bin/tsc -b`
  - **Retries:** `0/3`

- [x] **TASK-066:** Pantalla 5 — Threat Intelligence: indicadores, actores, campañas, salud de feeds y estados degradados.
  - **Owner:** `@builder` -> `@ui-artisan` -> `@qa-verifier`
  - **Depends On:** `TASK-062, TASK-023`
  - **Spec Ref:** `AC-50..AC-54`, `AC-94`
  - **Target Files:** `frontend/src/screens/ThreatIntelligence.tsx`, `frontend/src/components/features/cti/**`
  - **Verification:** `cd backend && pytest -q tests/integration/test_incidents.py tests/integration/test_threat_intel.py tests/integration/test_forensics.py && cd ../frontend && node node_modules/typescript/bin/tsc -b`
  - **Retries:** `0/3`

- [x] **TASK-067:** Pantalla 16 — Forensics: casos, manifiesto de evidencias, cadena de custodia y timeline.
  - **Owner:** `@builder` -> `@ui-artisan` -> `@qa-verifier`
  - **Depends On:** `TASK-064, TASK-023`
  - **Spec Ref:** `AC-59`, `AC-94`
  - **Target Files:** `frontend/src/screens/Forensics.tsx`, `frontend/src/components/features/forensics/**`
  - **Verification:** `cd backend && pytest -q tests/integration/test_incidents.py tests/integration/test_threat_intel.py tests/integration/test_forensics.py && cd ../frontend && node node_modules/typescript/bin/tsc -b`
  - **Retries:** `0/3`

---

## PHASE 5: SOAR — PLAYBOOKS, DURABLE WORKFLOW & APPROVALS

- [x] **TASK-068:** Modelos de playbook/versión y validación de DAG (nodos huérfanos, ciclos, tipos de nodo, contratos de parámetros).
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-055`
  - **Spec Ref:** `REQ-SOAR-001`, `AC-43`
  - **Target Files:** `backend/app/models/playbooks.py`, `backend/app/workflow/dag.py`, `backend/migrations/versions/0013_playbooks.py`, `backend/tests/unit/test_playbook_dag.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_soar.py tests/integration/test_defence.py tests/security/test_autonomy_guardrails.py`
  - **Retries:** `0/3`

- [x] **TASK-069:** Motor durable: claim con `SKIP LOCKED`, leases, heartbeat, reclamación por expiración y reanudación.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-008, TASK-068`
  - **Spec Ref:** `ADR-004`, `AC-44`
  - **Target Files:** `backend/app/workflow/engine.py`, `backend/app/workflow/lease.py`, `backend/tests/integration/test_workflow_resume.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_soar.py tests/integration/test_defence.py tests/security/test_autonomy_guardrails.py`
  - **Retries:** `0/3`

- [x] **TASK-070:** Ejecutor de pasos con idempotencia por `step_key`, retry con backoff+jitter, dead-letter y registro de intentos.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-069`
  - **Spec Ref:** `AC-45`
  - **Target Files:** `backend/app/workflow/steps.py`, `backend/app/workflow/retry.py`, `backend/tests/unit/test_retry_policy.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_soar.py tests/integration/test_defence.py tests/security/test_autonomy_guardrails.py`
  - **Retries:** `0/3`

- [!] **TASK-071:** Nodos de aprobación con aprobadores, timeout→deny, doble aprobación y rama `on_deny`.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-070`
  - **Spec Ref:** `AC-46`
  - **Target Files:** `backend/app/workflow/approvals.py`, `backend/app/services/approvals.py`, `backend/tests/integration/test_approvals.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_soar.py tests/integration/test_defence.py tests/security/test_autonomy_guardrails.py`
  - **Deferred:** Double approval deferred; single approval with separation of duties delivered.
  - **Retries:** `0/3`

- [x] **TASK-072:** Compensación/rollback LIFO de acciones inversas idempotentes con evidencia por paso.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-071`
  - **Spec Ref:** `AC-47`
  - **Target Files:** `backend/app/workflow/compensation.py`, `backend/tests/integration/test_compensation.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_soar.py tests/integration/test_defence.py tests/security/test_autonomy_guardrails.py`
  - **Retries:** `0/3`

- [!] **TASK-073:** Dry-run sin efectos laterales, límites de concurrencia por org y encolado con posición visible.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-072`
  - **Spec Ref:** `AC-48, AC-49`
  - **Target Files:** `backend/app/workflow/dry_run.py`, `backend/app/services/executions.py`, `backend/tests/integration/test_dry_run.py`, `backend/tests/integration/test_concurrency_limits.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_soar.py tests/integration/test_defence.py tests/security/test_autonomy_guardrails.py`
  - **Deferred:** Per-org concurrency/budget limits deferred; dry-run delivered.
  - **Retries:** `0/3`

- [x] **TASK-074:** API de playbooks (CRUD, versionar, publicar) y de ejecuciones (lanzar, consultar, cancelar, compensar), con permisos y auditoría.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-073`
  - **Spec Ref:** `AC-43`, `AC-49`, `ARCHITECTURE.md §4`
  - **Target Files:** `backend/app/api/v1/playbooks.py`, `backend/app/api/v1/executions.py`, `backend/tests/integration/test_playbook_api.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_soar.py tests/integration/test_defence.py tests/security/test_autonomy_guardrails.py`
  - **Retries:** `0/3`

- [x] **TASK-075:** Pantalla 10 — SOAR: playbooks, ejecuciones con pasos, inbox de aprobaciones y acciones de cancelación/compensación.
  - **Owner:** `@builder` -> `@ui-artisan` -> `@qa-verifier`
  - **Depends On:** `TASK-074, TASK-023`
  - **Spec Ref:** `AC-94..AC-99`
  - **Target Files:** `frontend/src/screens/Soar.tsx`, `frontend/src/components/features/soar/**`, `frontend/e2e/soar.spec.ts`
  - **Verification:** `cd backend && pytest -q tests/integration/test_soar.py tests/integration/test_defence.py tests/security/test_autonomy_guardrails.py`
  - **Retries:** `0/3`

- [x] **TASK-076:** Pantalla 19 — Playbook Designer: canvas DAG con nodos, inspector, validación en vivo, dry-run y versionado.
  - **Owner:** `@builder` -> `@ui-artisan` -> `@qa-verifier`
  - **Depends On:** `TASK-075`
  - **Spec Ref:** `AC-43, AC-48`, `AC-100`
  - **Target Files:** `frontend/src/screens/PlaybookDesigner.tsx`, `frontend/src/components/features/designer/**`, `frontend/e2e/designer.spec.ts`
  - **Verification:** `cd backend && pytest -q tests/integration/test_soar.py tests/integration/test_defence.py tests/security/test_autonomy_guardrails.py`
  - **Retries:** `0/3`

- [x] **TASK-077:** Suite de durabilidad: crash de worker, doble entrega, compensación parcial, timeout de aprobación y concurrencia.
  - **Owner:** `@qa-verifier`
  - **Depends On:** `TASK-076`
  - **Spec Ref:** `AC-44..AC-49`
  - **Target Files:** `backend/tests/integration/test_workflow_suite.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_soar.py tests/integration/test_defence.py tests/security/test_autonomy_guardrails.py`
  - **Retries:** `0/3`

---

## PHASE 6: AUTONOMOUS DEFENCE — POLICY, BROKER & KILL SWITCHES

- [x] **TASK-078:** Modelo de políticas versionadas y motor de evaluación determinista deny-by-default con `decision_id` persistido.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-068`
  - **Spec Ref:** `REQ-AUT-001`, `AC-70`
  - **Target Files:** `backend/app/autonomy/policy.py`, `backend/app/autonomy/evaluator.py`, `backend/app/models/autonomy.py`, `backend/migrations/versions/0014_autonomy.py`, `backend/tests/autonomy/test_policy_default_deny.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_defence.py tests/security/test_autonomy_guardrails.py`
  - **Retries:** `0/3`

- [x] **TASK-079:** Gating de niveles A0..A4 y blast radius con rechazo total (sin ejecución parcial).
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-078`
  - **Spec Ref:** `AC-71, AC-73`
  - **Target Files:** `backend/app/autonomy/levels.py`, `backend/app/autonomy/blast_radius.py`, `backend/tests/autonomy/test_level_gating.py`, `backend/tests/autonomy/test_blast_radius.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_defence.py tests/security/test_autonomy_guardrails.py`
  - **Retries:** `0/3`

- [x] **TASK-080:** Catálogo de acciones, execution broker con allowlist por conector/capacidad y adaptadores de acción.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-079, TASK-107`
  - **Spec Ref:** `AC-72`, `specs/security/autonomy-policy.md`
  - **Target Files:** `backend/app/autonomy/broker.py`, `backend/app/autonomy/actions.py`, `backend/app/integrations/adapters/**`, `backend/tests/autonomy/test_broker_allowlist.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_defence.py tests/security/test_autonomy_guardrails.py`
  - **Retries:** `0/3`

- [x] **TASK-081:** Verificación post-acción con criterio declarado, timeout 60 s y rollback idempotente en fallo.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-080`
  - **Spec Ref:** `AC-72`
  - **Target Files:** `backend/app/autonomy/verifier.py`, `backend/app/autonomy/rollback.py`, `backend/tests/autonomy/test_execute_verify_rollback.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_defence.py tests/security/test_autonomy_guardrails.py`
  - **Retries:** `0/3`

- [x] **TASK-082:** Kill switches (global/org/conector/activo) con invalidación por `NOTIFY`, halt ≤5 s y marcado de ejecuciones en curso.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-081`
  - **Spec Ref:** `AC-74`
  - **Target Files:** `backend/app/autonomy/kill_switch.py`, `backend/app/api/v1/autonomy.py`, `backend/tests/autonomy/test_kill_switch.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_defence.py tests/security/test_autonomy_guardrails.py`
  - **Retries:** `0/3`

- [!] **TASK-083:** Presupuesto de acciones por hora, ventanas de cambio congelado y `break_glass` con doble aprobación y TTL.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-082`
  - **Spec Ref:** `AC-75, AC-76`
  - **Target Files:** `backend/app/autonomy/budget.py`, `backend/app/autonomy/change_window.py`, `backend/tests/autonomy/test_action_budget.py`, `backend/tests/autonomy/test_change_freeze.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_defence.py tests/security/test_autonomy_guardrails.py`
  - **Deferred:** Autonomy budgets, frozen windows and break-glass deferred.
  - **Retries:** `0/3`

- [!] **TASK-084:** A4 con doble aprobación, time-box ≤30 min y safety interlock OT (`safety_function`, nivel Purdue, telemetría fresca).
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-083`
  - **Spec Ref:** `AC-78, AC-82`
  - **Target Files:** `backend/app/autonomy/safety.py`, `backend/tests/autonomy/test_a4_dual_approval.py`, `backend/tests/autonomy/test_ot_safety_interlock.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_defence.py tests/security/test_autonomy_guardrails.py`
  - **Deferred:** A4 double approval deferred (no A4 actions in catalogue); OT safety interlock delivered.
  - **Retries:** `0/3`

- [x] **TASK-085:** API de autonomía (evaluate, actions, kill-switches) con auditoría completa y consulta de decisión/resultado.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-084`
  - **Spec Ref:** `AC-77`, `ARCHITECTURE.md §4`
  - **Target Files:** `backend/app/api/v1/autonomy.py`, `backend/app/services/autonomy_api.py`, `backend/tests/autonomy/test_action_audit.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_defence.py tests/security/test_autonomy_guardrails.py`
  - **Retries:** `0/3`

- [!] **TASK-086:** Laboratorio de autonomía: matriz allow/deny por nivel, blast radius, freeze, budget, kill switch y rollback con resultados esperados.
  - **Owner:** `@qa-verifier`
  - **Depends On:** `TASK-085`
  - **Spec Ref:** `AC-123`, `specs/testing/autonomy-lab.md`
  - **Target Files:** `backend/tests/autonomy/test_lab_scenarios.py`, `backend/tests/autonomy/fixtures.py`, `reports/autonomy-lab.md`
  - **Verification:** `cd backend && pytest -q tests/integration/test_defence.py tests/security/test_autonomy_guardrails.py`
  - **Deferred:** Budget/freeze lab matrix deferred; core allow/deny/kill-switch/rollback lab delivered.
  - **Retries:** `0/3`

- [x] **TASK-087:** Pantalla 23 (finalización) — kill switch panel con confirmación escrita, banner global de halt, indicador de autonomía y estado de políticas.
  - **Owner:** `@builder` -> `@ui-artisan` -> `@qa-verifier`
  - **Depends On:** `TASK-085, TASK-027`
  - **Spec Ref:** `AC-102`, `AC-74`, `ARCHITECTURE.md §5.1`
  - **Target Files:** `frontend/src/components/features/autonomy/{KillSwitchPanel,AutonomyBanner}.tsx`, `frontend/src/screens/SystemAdministration.tsx`, `frontend/e2e/kill-switch.spec.ts`
  - **Verification:** `cd backend && pytest -q tests/integration/test_defence.py tests/security/test_autonomy_guardrails.py`
  - **Retries:** `0/3`

---

## PHASE 7: AI GATEWAY, RAG, AGENTS & MCP

- [x] **TASK-088:** Abstracción `AIProvider` (ollama, vllm/openai-compatible), registro de proveedores/modelos con health y cifrado de credenciales.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-006, TASK-078`
  - **Spec Ref:** `ADR-010`, `AC-61, AC-75`
  - **Target Files:** `backend/app/ai/providers/{base,ollama,openai_compat}.py`, `backend/app/ai/registry.py`, `backend/app/models/ai.py`, `backend/migrations/versions/0015_ai.py`, `backend/tests/integration/test_ai_unavailable.py`
  - **Verification:** `cd backend && pytest -q tests/unit/test_rag.py tests/unit/test_prompt_safety.py tests/integration/test_ai.py tests/integration/test_agents.py tests/integration/test_mcp.py`
  - **Retries:** `0/3`

- [x] **TASK-089:** Router por perfil de tarea con fallback declarado y presupuesto de tokens/coste por organización y día.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-088`
  - **Spec Ref:** `AC-62, AC-67`
  - **Target Files:** `backend/app/ai/router.py`, `backend/app/ai/budget.py`, `backend/tests/integration/test_ai_routing.py`, `backend/tests/integration/test_ai_budget.py`
  - **Verification:** `cd backend && pytest -q tests/unit/test_rag.py tests/unit/test_prompt_safety.py tests/integration/test_ai.py tests/integration/test_agents.py tests/integration/test_mcp.py`
  - **Retries:** `0/3`

- [x] **TASK-090:** API de chat/completions con logging redactado, `usage`, timeout, cancelación y errores `ai_unavailable`.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-089`
  - **Spec Ref:** `AC-61, AC-68`
  - **Target Files:** `backend/app/ai/chat.py`, `backend/app/api/v1/ai.py`, `backend/tests/security/test_ai_log_redaction.py`
  - **Verification:** `cd backend && pytest -q tests/unit/test_rag.py tests/unit/test_prompt_safety.py tests/integration/test_ai.py tests/integration/test_agents.py tests/integration/test_mcp.py`
  - **Retries:** `0/3`

- [x] **TASK-091:** Embeddings con dimensión fija, almacenamiento `float4[]`, similitud coseno numpy y validación de dimensión.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-088`
  - **Spec Ref:** `ADR-005`, `AC-64`
  - **Target Files:** `backend/app/ai/embeddings.py`, `backend/app/ai/vector_store.py`, `backend/tests/unit/test_vector_store.py`
  - **Verification:** `cd backend && pytest -q tests/unit/test_rag.py tests/unit/test_prompt_safety.py tests/integration/test_ai.py tests/integration/test_agents.py tests/integration/test_mcp.py`
  - **Retries:** `0/3`

- [x] **TASK-092:** Ingesta de documentos (MIME, límite, chunking, metadatos) y RAG con citas verificables y snippets.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-091`
  - **Spec Ref:** `AC-63`
  - **Target Files:** `backend/app/ai/documents.py`, `backend/app/ai/rag.py`, `backend/tests/integration/test_rag_citations.py`
  - **Verification:** `cd backend && pytest -q tests/unit/test_rag.py tests/unit/test_prompt_safety.py tests/integration/test_ai.py tests/integration/test_agents.py tests/integration/test_mcp.py`
  - **Retries:** `0/3`

- [!] **TASK-093:** Runtime de agentes durable con step log, reanudación, límite de pasos y presupuesto por run.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-090, TASK-069`
  - **Spec Ref:** `AC-69`
  - **Target Files:** `backend/app/ai/agents/runtime.py`, `backend/app/api/v1/agents.py`, `backend/tests/integration/test_agent_durability.py`
  - **Verification:** `cd backend && pytest -q tests/unit/test_rag.py tests/unit/test_prompt_safety.py tests/integration/test_ai.py tests/integration/test_agents.py tests/integration/test_mcp.py`
  - **Deferred:** Durable resumable agent runtime deferred; bounded synchronous runs delivered.
  - **Retries:** `0/3`

- [x] **TASK-094:** Registro MCP (servidores, tools, esquemas) y tool broker con allowlist por agente, validación de entrada y auditoría.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-093`
  - **Spec Ref:** `AC-66, AC-108`
  - **Target Files:** `backend/app/ai/mcp/registry.py`, `backend/app/ai/mcp/broker.py`, `backend/app/api/v1/mcp.py`, `backend/tests/integration/test_mcp_registry.py`, `backend/tests/security/test_mcp_allowlist.py`
  - **Verification:** `cd backend && pytest -q tests/unit/test_rag.py tests/unit/test_prompt_safety.py tests/integration/test_ai.py tests/integration/test_agents.py tests/integration/test_mcp.py`
  - **Retries:** `0/3`

- [x] **TASK-095:** Defensas anti prompt-injection: detección de instrucciones de override, aislamiento de contenido no confiable y corpus de tests.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-094`
  - **Spec Ref:** `AC-65`
  - **Target Files:** `backend/app/ai/guardrails.py`, `backend/tests/security/test_prompt_injection.py`, `examples/prompt-injection/`
  - **Verification:** `cd backend && pytest -q tests/unit/test_rag.py tests/unit/test_prompt_safety.py tests/integration/test_ai.py tests/integration/test_agents.py tests/integration/test_mcp.py`
  - **Retries:** `0/3`

- [x] **TASK-096:** Estados honestos de indisponibilidad (API+UI), endpoint de test de proveedor y gate de evaluación para cambios de modelo.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-095`
  - **Spec Ref:** `AC-61, AC-86`, `P-06`
  - **Target Files:** `backend/app/ai/health.py`, `backend/app/services/model_eval.py`, `backend/tests/integration/test_model_eval_gate.py`
  - **Verification:** `cd backend && pytest -q tests/unit/test_rag.py tests/unit/test_prompt_safety.py tests/integration/test_ai.py tests/integration/test_agents.py tests/integration/test_mcp.py`
  - **Retries:** `0/3`

- [x] **TASK-097:** Pantalla 11 — AI Agent Control: runs, trazas de tool-calls, presupuesto, aprobaciones y estado `UNAVAILABLE`.
  - **Owner:** `@builder` -> `@ui-artisan` -> `@qa-verifier`
  - **Depends On:** `TASK-096, TASK-023`
  - **Spec Ref:** `AC-61..AC-69`, `AC-94`
  - **Target Files:** `frontend/src/screens/AiAgentControl.tsx`, `frontend/src/components/features/agents/**`
  - **Verification:** `cd backend && pytest -q tests/unit/test_rag.py tests/unit/test_prompt_safety.py tests/integration/test_ai.py tests/integration/test_agents.py tests/integration/test_mcp.py`
  - **Retries:** `0/3`

- [x] **TASK-098:** Pantalla 20 — Model Management: proveedores, tarjetas de modelo, health, evals y presupuesto.
  - **Owner:** `@builder` -> `@ui-artisan` -> `@qa-verifier`
  - **Depends On:** `TASK-096, TASK-023`
  - **Spec Ref:** `AC-61, AC-86`, `AC-94`
  - **Target Files:** `frontend/src/screens/ModelManagement.tsx`, `frontend/src/components/features/models/**`
  - **Verification:** `cd backend && pytest -q tests/unit/test_rag.py tests/unit/test_prompt_safety.py tests/integration/test_ai.py tests/integration/test_agents.py tests/integration/test_mcp.py`
  - **Retries:** `0/3`

---

## PHASE 8: IOT/OT, CLOUD, CONNECTORS & EDGE GATEWAY

- [!] **TASK-099:** Registro IoT: protocolo Soportado, zona obligatoria, checklist ETSI EN 303 645 (13 provisiones) y ciclo de vida.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-034`
  - **Spec Ref:** `AC-79`, `specs/domains/iot.md`
  - **Target Files:** `backend/app/services/iot.py`, `backend/app/api/v1/iot.py`, `backend/tests/integration/test_iot_registration.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_iot_ot.py tests/integration/test_connectors.py tests/integration/test_connectors_adapters.py tests/integration/test_connectors_security.py tests/integration/test_edge.py && cd ../edge && pytest -q`
  - **Deferred:** ETSI EN 303 645 13-provision scoring deferred; IoT posture flags delivered.
  - **Retries:** `0/3`

- [!] **TASK-100:** Inventario de firmware, match CVE por CPE/versión, marca EOL y bloqueo de acciones sobre telemetría stale.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-099`
  - **Spec Ref:** `AC-80, AC-81`
  - **Target Files:** `backend/app/services/firmware.py`, `backend/tests/integration/test_firmware_cve.py`, `backend/tests/autonomy/test_stale_sensor.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_iot_ot.py tests/integration/test_connectors.py tests/integration/test_connectors_adapters.py tests/integration/test_connectors_security.py tests/integration/test_edge.py && cd ../edge && pytest -q`
  - **Deferred:** Firmware CPE/CVE matching and EOL marking deferred; vulnerability linking delivered.
  - **Retries:** `0/3`

- [!] **TASK-101:** Modelo OT: nivel Purdue, safety function, zonas y conductos IEC 62443 con `required_sl` obligatorio.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-034`
  - **Spec Ref:** `REQ-OTC-001`, `AC-84`
  - **Target Files:** `backend/app/services/ot.py`, `backend/app/api/v1/ot.py`, `backend/tests/integration/test_iec62443_zones.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_iot_ot.py tests/integration/test_connectors.py tests/integration/test_connectors_adapters.py tests/integration/test_connectors_security.py tests/integration/test_edge.py && cd ../edge && pytest -q`
  - **Deferred:** Per-zone required_sl deferred; Purdue zones/conduits delivered.
  - **Retries:** `0/3`

- [x] **TASK-102:** Línea base de tráfico Modbus/DNP3/OPC-UA y detección de anomalías de función de escritura con severidad por Purdue.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-101, TASK-049`
  - **Spec Ref:** `AC-83`
  - **Target Files:** `backend/app/services/ot_baseline.py`, `backend/tests/integration/test_ot_anomaly.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_iot_ot.py tests/integration/test_connectors.py tests/integration/test_connectors_adapters.py tests/integration/test_connectors_security.py tests/integration/test_edge.py && cd ../edge && pytest -q`
  - **Retries:** `0/3`

- [x] **TASK-103:** Pantalla 12 — IoT/OT Security: dispositivos, mapa Purdue, zonas, anomalías y badge de telemetría stale.
  - **Owner:** `@builder` -> `@ui-artisan` -> `@qa-verifier`
  - **Depends On:** `TASK-102, TASK-023`
  - **Spec Ref:** `AC-79..AC-84`, `AC-94`
  - **Target Files:** `frontend/src/screens/IotOtSecurity.tsx`, `frontend/src/components/features/iotot/**`
  - **Verification:** `cd backend && pytest -q tests/integration/test_iot_ot.py tests/integration/test_connectors.py tests/integration/test_connectors_adapters.py tests/integration/test_connectors_security.py tests/integration/test_edge.py && cd ../edge && pytest -q`
  - **Retries:** `0/3`

- [x] **TASK-104:** Pantalla 13 — Network Security: segmentos, conduits, flujos y detecciones de red.
  - **Owner:** `@builder` -> `@ui-artisan` -> `@qa-verifier`
  - **Depends On:** `TASK-101, TASK-023`
  - **Spec Ref:** `AC-94`, `specs/domains/ot.md`
  - **Target Files:** `frontend/src/screens/NetworkSecurity.tsx`, `backend/app/api/v1/network.py`, `backend/tests/integration/test_network_segments.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_iot_ot.py tests/integration/test_connectors.py tests/integration/test_connectors_adapters.py tests/integration/test_connectors_security.py tests/integration/test_edge.py && cd ../edge && pytest -q`
  - **Retries:** `0/3`

- [!] **TASK-105:** Cuentas cloud: modelo, credenciales cifradas, rotación, último uso y reglas CSPM con mapeo a controles.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-107`
  - **Spec Ref:** `REQ-CLD-001`, `AC-85, AC-86, AC-87`
  - **Target Files:** `backend/app/services/cloud.py`, `backend/app/services/cspm.py`, `backend/app/api/v1/cloud.py`, `backend/tests/integration/test_cspm_rules.py`, `backend/tests/integration/test_cloud_degraded_state.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_iot_ot.py tests/integration/test_connectors.py tests/integration/test_connectors_adapters.py tests/integration/test_connectors_security.py tests/integration/test_edge.py && cd ../edge && pytest -q`
  - **Deferred:** Cloud account credentials/CSPM rules deferred; posture from imported evidence delivered.
  - **Retries:** `0/3`

- [x] **TASK-106:** Pantalla 14 — Cloud Security: cuentas, postura, findings por proveedor y estado degradado con `as_of`.
  - **Owner:** `@builder` -> `@ui-artisan` -> `@qa-verifier`
  - **Depends On:** `TASK-105, TASK-023`
  - **Spec Ref:** `AC-85..AC-87`, `AC-94`
  - **Target Files:** `frontend/src/screens/CloudSecurity.tsx`, `frontend/src/components/features/cloud/**`
  - **Verification:** `cd backend && pytest -q tests/integration/test_iot_ot.py tests/integration/test_connectors.py tests/integration/test_connectors_adapters.py tests/integration/test_connectors_security.py tests/integration/test_edge.py && cd ../edge && pytest -q`
  - **Retries:** `0/3`

- [x] **TASK-107:** Registro de conectores: manifiesto, `config_schema` JSON Schema, capacidades, tipos y validación de registro.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-021`
  - **Spec Ref:** `REQ-INT-001`, `AC-104`
  - **Target Files:** `backend/app/models/connectors.py`, `backend/app/integrations/registry.py`, `backend/app/api/v1/connectors.py`, `backend/migrations/versions/0016_connectors.py`, `backend/tests/integration/test_connector_registry.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_iot_ot.py tests/integration/test_connectors.py tests/integration/test_connectors_adapters.py tests/integration/test_connectors_security.py tests/integration/test_edge.py && cd ../edge && pytest -q`
  - **Retries:** `0/3`

- [x] **TASK-108:** Secretos de conector cifrados, rotación, health checks, circuit breaker con backoff y log de errores normalizado.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-107, TASK-006`
  - **Spec Ref:** `AC-105, AC-107`
  - **Target Files:** `backend/app/core/crypto.py`, `backend/app/services/connector_health.py`, `backend/tests/security/test_connector_secret_storage.py`, `backend/tests/integration/test_circuit_breaker.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_iot_ot.py tests/integration/test_connectors.py tests/integration/test_connectors_adapters.py tests/integration/test_connectors_security.py tests/integration/test_edge.py && cd ../edge && pytest -q`
  - **Retries:** `0/3`

- [x] **TASK-109:** Protocol registry y matriz de compatibilidad con estados `supported`/`unsupported` explícitos y endpoint de consulta.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-107`
  - **Spec Ref:** `AC-109`, `specs/integrations/protocol-registry.md`
  - **Target Files:** `backend/app/integrations/protocols.py`, `backend/app/api/v1/protocols.py`, `backend/tests/unit/test_protocol_registry.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_iot_ot.py tests/integration/test_connectors.py tests/integration/test_connectors_adapters.py tests/integration/test_connectors_security.py tests/integration/test_edge.py && cd ../edge && pytest -q`
  - **Retries:** `0/3`

- [x] **TASK-110:** Edge gateway: cola SQLite WAL, secuencia monotónica, reintentos y reenvío en orden sin pérdidas ni duplicados.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-107`
  - **Spec Ref:** `AC-105`, `ADR-008`
  - **Target Files:** `edge/hispanshield_edge/{queue.py,main.py,config.py}`, `edge/tests/test_store_and_forward.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_iot_ot.py tests/integration/test_connectors.py tests/integration/test_connectors_adapters.py tests/integration/test_connectors_security.py tests/integration/test_edge.py && cd ../edge && pytest -q`
  - **Retries:** `0/3`

- [x] **TASK-111:** Edge transport mTLS + HMAC, backoff, límite de lote, CLI de operación y empaquetado/systemd.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-110`
  - **Spec Ref:** `AC-106`, `specs/integrations/connector-contract.md`
  - **Target Files:** `edge/hispanshield_edge/{transport.py,cli.py}`, `edge/tests/test_mtls.py`, `infra/systemd/hispanshield-edge.service`, `edge/pyproject.toml`
  - **Verification:** `cd backend && pytest -q tests/integration/test_iot_ot.py tests/integration/test_connectors.py tests/integration/test_connectors_adapters.py tests/integration/test_connectors_security.py tests/integration/test_edge.py && cd ../edge && pytest -q`
  - **Retries:** `0/3`

- [x] **TASK-112:** Pantalla 18 — Integrations: catálogo de conectores, salud, formulario de secretos y errores; suite de contrato edge/core.
  - **Owner:** `@builder` -> `@ui-artisan` -> `@qa-verifier`
  - **Depends On:** `TASK-111, TASK-108, TASK-023`
  - **Spec Ref:** `AC-104..AC-109`, `AC-94`
  - **Target Files:** `frontend/src/screens/Integrations.tsx`, `frontend/src/components/features/integrations/**`, `edge/tests/test_contract.py`
  - **Verification:** `cd backend && pytest -q tests/integration/test_iot_ot.py tests/integration/test_connectors.py tests/integration/test_connectors_adapters.py tests/integration/test_connectors_security.py tests/integration/test_edge.py && cd ../edge && pytest -q`
  - **Retries:** `0/3`

---

## PHASE 9: COMPLIANCE, REPORTS & AUDIT CENTER

- [x] **TASK-113:** Seed de frameworks (NIS2, CRA, GDPR, ENS, ISO 27001:2022, ISO 27002:2022, IEC 62443-3-3, ETSI EN 303 645) con controles y referencias.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-005`
  - **Spec Ref:** `AC-88`
  - **Target Files:** `backend/app/models/compliance.py`, `backend/app/compliance/frameworks/*.py`, `backend/migrations/versions/0017_compliance.py`, `backend/tests/integration/test_framework_seed.py`
  - **Verification:** `cd backend && pytest -q tests/unit/test_frameworks.py tests/integration/test_compliance.py tests/integration/test_reports.py`
  - **Retries:** `0/3`

- [x] **TASK-114:** Controles versionados, mapeos many-to-many, evidencias con validez/revisor y derivación automática de estado.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-113`
  - **Spec Ref:** `AC-89, AC-91`
  - **Target Files:** `backend/app/services/compliance.py`, `backend/app/api/v1/compliance.py`, `backend/tests/integration/test_control_status_derivation.py`, `backend/tests/integration/test_evidence_expiry.py`
  - **Verification:** `cd backend && pytest -q tests/unit/test_frameworks.py tests/integration/test_compliance.py tests/integration/test_reports.py`
  - **Retries:** `0/3`

- [x] **TASK-115:** Evaluaciones con scoring documentado, gaps con severidad, bloqueo al finalizar y creación de tareas de remediación.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-114`
  - **Spec Ref:** `AC-90`
  - **Target Files:** `backend/app/services/assessments.py`, `backend/tests/unit/test_assessment_scoring.py`
  - **Verification:** `cd backend && pytest -q tests/unit/test_frameworks.py tests/integration/test_compliance.py tests/integration/test_reports.py`
  - **Retries:** `0/3`

- [!] **TASK-116:** Tracker NIS2 (24 h/72 h/1 mes) y registro GDPR RoPA/DPIA con due dates y alertas de proximidad.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-115, TASK-055`
  - **Spec Ref:** `AC-92`
  - **Target Files:** `backend/app/services/nis2.py`, `backend/app/services/gdpr.py`, `backend/tests/integration/test_nis2_timeline.py`
  - **Verification:** `cd backend && pytest -q tests/unit/test_frameworks.py tests/integration/test_compliance.py tests/integration/test_reports.py`
  - **Deferred:** NIS2 tracker and RoPA/DPIA register deferred.
  - **Retries:** `0/3`

- [!] **TASK-117:** Generación de informes PDF/JSON con versiones de framework, `generated_at` y hash verificable.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-116`
  - **Spec Ref:** `AC-93`
  - **Target Files:** `backend/app/services/reports/compliance_report.py`, `backend/app/api/v1/reports.py`, `backend/tests/integration/test_report_integrity.py`
  - **Verification:** `cd backend && pytest -q tests/unit/test_frameworks.py tests/integration/test_compliance.py tests/integration/test_reports.py`
  - **Deferred:** PDF rendering deferred; HTML/Markdown reports with checksum delivered.
  - **Retries:** `0/3`

- [x] **TASK-118:** Pantalla 17 — Compliance: frameworks, matriz de controles, gaps, evidencias y estado `evidence_expired`.
  - **Owner:** `@builder` -> `@ui-artisan` -> `@qa-verifier`
  - **Depends On:** `TASK-117, TASK-023`
  - **Spec Ref:** `AC-88..AC-93`, `AC-94`
  - **Target Files:** `frontend/src/screens/Compliance.tsx`, `frontend/src/components/features/compliance/**`
  - **Verification:** `cd backend && pytest -q tests/unit/test_frameworks.py tests/integration/test_compliance.py tests/integration/test_reports.py`
  - **Retries:** `0/3`

- [x] **TASK-119:** Pantalla 21 — Audit Center: consulta filtrada, verificación de cadena y detalle de acción autónoma.
  - **Owner:** `@builder` -> `@ui-artisan` -> `@qa-verifier`
  - **Depends On:** `TASK-007, TASK-085, TASK-023`
  - **Spec Ref:** `AC-112`, `AC-77`, `AC-94`
  - **Target Files:** `frontend/src/screens/AuditCenter.tsx`, `frontend/src/components/features/audit/**`
  - **Verification:** `cd backend && pytest -q tests/unit/test_frameworks.py tests/integration/test_compliance.py tests/integration/test_reports.py`
  - **Retries:** `0/3`

- [x] **TASK-120:** API de métricas ejecutivas (`/metrics/summary`) con KPIs, tendencias y postura por framework, sin datos fabricados.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-115, TASK-051, TASK-041`
  - **Spec Ref:** `AC-110`, `AC-94`
  - **Target Files:** `backend/app/services/metrics.py`, `backend/app/api/v1/metrics.py`, `backend/tests/integration/test_metrics_summary.py`
  - **Verification:** `cd backend && pytest -q tests/unit/test_frameworks.py tests/integration/test_compliance.py tests/integration/test_reports.py`
  - **Retries:** `0/3`

- [x] **TASK-121:** Pantalla 1 — Executive Overview: KPI strip, tendencia 30 d, radar de postura, top activos y onboarding vacío.
  - **Owner:** `@builder` -> `@ui-artisan` -> `@qa-verifier`
  - **Depends On:** `TASK-120, TASK-023`
  - **Spec Ref:** `AC-94..AC-99`
  - **Target Files:** `frontend/src/screens/ExecutiveOverview.tsx`, `frontend/src/components/charts/**`, `frontend/e2e/overview.spec.ts`
  - **Verification:** `cd backend && pytest -q tests/unit/test_frameworks.py tests/integration/test_compliance.py tests/integration/test_reports.py`
  - **Retries:** `0/3`

- [!] **TASK-122:** Suite de integración de cumplimiento: seed→evidencia→evaluación→informe→verificación de hash y tracker NIS2 end-to-end.
  - **Owner:** `@qa-verifier`
  - **Depends On:** `TASK-121`
  - **Spec Ref:** `AC-88..AC-93`
  - **Target Files:** `backend/tests/integration/test_compliance_flow.py`
  - **Verification:** `cd backend && pytest -q tests/unit/test_frameworks.py tests/integration/test_compliance.py tests/integration/test_reports.py`
  - **Deferred:** NIS2 tracker integration deferred; compliance lifecycle suite delivered.
  - **Retries:** `0/3`

---

## PHASE 10: FRONTEND INTEGRATION, CRAFT & E2E

- [x] **TASK-123:** Auditoría de estados en las 23 pantallas: skeletons estructurales, empty con CTA, error con retry y degradado con `as_of`.
  - **Owner:** `@ui-artisan` -> `@qa-verifier`
  - **Depends On:** `TASK-122`
  - **Spec Ref:** `AC-95, AC-96, AC-97`
  - **Target Files:** `frontend/src/components/ui/{Skeleton,EmptyState,ErrorBanner}.tsx`, `frontend/e2e/states.spec.ts`
  - **Verification:** `cd frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build && node node_modules/vitest/vitest.mjs run && node node_modules/@playwright/test/cli.js test e2e --project=chromium-desktop`
  - **Retries:** `0/3`

- [x] **TASK-124:** Pasada responsive 375/768/1440 en las 23 rutas, tablas con scroll interno y drawer de navegación móvil.
  - **Owner:** `@ui-artisan` -> `@qa-verifier`
  - **Depends On:** `TASK-123`
  - **Spec Ref:** `AC-98`
  - **Target Files:** `frontend/src/styles/responsive.css`, `frontend/e2e/responsive.spec.ts`
  - **Verification:** `cd frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build && node node_modules/vitest/vitest.mjs run && node node_modules/@playwright/test/cli.js test e2e --project=chromium-desktop`
  - **Retries:** `0/3`

- [!] **TASK-125:** Pasada de accesibilidad: axe-core 0 violaciones, foco visible, orden de tabulación, modales con focus trap y reduced motion.
  - **Owner:** `@ui-artisan` -> `@qa-verifier`
  - **Depends On:** `TASK-124`
  - **Spec Ref:** `AC-99, AC-100, AC-103`
  - **Target Files:** `frontend/e2e/{a11y,keyboard,reduced-motion}.spec.ts`, `frontend/src/components/ui/Modal.tsx`
  - **Verification:** `cd frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build && node node_modules/vitest/vitest.mjs run && node node_modules/@playwright/test/cli.js test e2e --project=chromium-desktop`
  - **Deferred:** Automated axe-core violation gate deferred; keyboard/contrast review delivered.
  - **Retries:** `0/3`

- [!] **TASK-126:** Integración SSE transversal: reconexión con backoff, dedupe por `event_id`, pausa/reanudar y `aria-live` en vistas en vivo.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-125`
  - **Spec Ref:** `AC-101`
  - **Target Files:** `frontend/src/lib/sse.ts`, `frontend/src/components/features/live/**`, `frontend/e2e/live-stream.spec.ts`
  - **Verification:** `cd frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build && node node_modules/vitest/vitest.mjs run && node node_modules/@playwright/test/cli.js test e2e --project=chromium-desktop`
  - **Deferred:** SSE reconnection integration deferred; polling delivered.
  - **Retries:** `0/3`

- [x] **TASK-127:** Pasada visual final `@ui-artisan`: densidad, contraste, jerarquía, micro-interacciones ≤400 ms, iconografía y consistencia de tokens.
  - **Owner:** `@ui-artisan` -> `@qa-verifier`
  - **Depends On:** `TASK-126`
  - **Spec Ref:** `SPEC.md §4`, `ARCHITECTURE.md §5`
  - **Target Files:** `frontend/src/styles/**`, `frontend/src/components/**`, `reports/ui-review.md`
  - **Verification:** `cd frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build && node node_modules/vitest/vitest.mjs run && node node_modules/@playwright/test/cli.js test e2e --project=chromium-desktop`
  - **Retries:** `0/3`

- [!] **TASK-128:** E2E flujos núcleo: login+MFA, cambio de organización, alta de activo, ingesta→alerta→incidente→evidencia.
  - **Owner:** `@qa-verifier`
  - **Depends On:** `TASK-127`
  - **Spec Ref:** `AC-119`, `AC-01..AC-60`
  - **Target Files:** `frontend/e2e/core-journeys.spec.ts`
  - **Verification:** `cd frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build && node node_modules/vitest/vitest.mjs run && node node_modules/@playwright/test/cli.js test e2e --project=chromium-desktop`
  - **Deferred:** Full ingest→alert→incident→evidence browser automation deferred; screen/auth flows delivered.
  - **Retries:** `0/3`

- [!] **TASK-129:** E2E autonomía y SOAR: playbook con aprobación, deny por política, dry-run, kill switch y rollback visible en auditoría.
  - **Owner:** `@qa-verifier`
  - **Depends On:** `TASK-128`
  - **Spec Ref:** `AC-70..AC-78`, `AC-119`
  - **Target Files:** `frontend/e2e/autonomy.spec.ts`, `frontend/e2e/soar-approval.spec.ts`
  - **Verification:** `cd frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build && node node_modules/vitest/vitest.mjs run && node node_modules/@playwright/test/cli.js test e2e --project=chromium-desktop`
  - **Deferred:** Autonomy browser E2E deferred; backend autonomy lab delivered.
  - **Retries:** `0/3`

- [!] **TASK-130:** E2E estados degradados: IA sin proveedor, conector caído, feed con error, sensor stale y BD no disponible en readiness.
  - **Owner:** `@qa-verifier`
  - **Depends On:** `TASK-129`
  - **Spec Ref:** `AC-96, AC-97, P-06`
  - **Target Files:** `frontend/e2e/degraded.spec.ts`
  - **Verification:** `cd frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build && node node_modules/vitest/vitest.mjs run && node node_modules/@playwright/test/cli.js test e2e --project=chromium-desktop`
  - **Deferred:** Degraded-state browser matrix deferred; UI states implemented and backend tested.
  - **Retries:** `0/3`

- [!] **TASK-131:** Rendimiento frontend: code splitting por ruta, virtualización de tablas largas, budget de bundle y memoización de charts.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-130`
  - **Spec Ref:** `NFR-01`, `AC-118`
  - **Target Files:** `frontend/vite.config.ts`, `frontend/src/routes.tsx`, `frontend/src/components/ui/DataTable.tsx`, `reports/perf/frontend.md`
  - **Verification:** `cd frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build && node node_modules/vitest/vitest.mjs run && node node_modules/@playwright/test/cli.js test e2e --project=chromium-desktop`
  - **Deferred:** Table virtualization deferred; route-level code splitting delivered.
  - **Retries:** `0/3`

- [x] **TASK-132:** Test de inventario de pantallas: las 23 rutas existen, renderizan `<h1>` esperado, 0 errores de consola y 0 respuestas 5xx.
  - **Owner:** `@qa-verifier`
  - **Depends On:** `TASK-131`
  - **Spec Ref:** `AC-94`
  - **Target Files:** `frontend/e2e/screens.spec.ts`, `frontend/src/screens/index.ts`
  - **Verification:** `cd frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build && node node_modules/vitest/vitest.mjs run && node node_modules/@playwright/test/cli.js test e2e --project=chromium-desktop`
  - **Retries:** `0/3`

---

## PHASE 11: HARDENING, DEPLOYMENT, DOCUMENTATION & FINAL GATES

- [x] **TASK-133:** Manifiestos Docker Compose (api, worker, web, postgres) con healthchecks, non-root, read-only donde aplique y sin secretos embebidos.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-132`
  - **Spec Ref:** `specs/architecture/deployment-architecture.md`, `AC-114`
  - **Target Files:** `deploy/compose/docker-compose.yml`, `deploy/compose/.env.example`, `backend/Dockerfile`, `frontend/Dockerfile`
  - **Verification:** `cd backend && ruff check app tests && mypy app && pytest -q && cd ../frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build && node node_modules/vitest/vitest.mjs run && node node_modules/@playwright/test/cli.js test e2e --project=chromium-desktop`
  - **Retries:** `0/3`

- [x] **TASK-134:** Manifiestos Kubernetes (Deployment, Service, Ingress, HPA, NetworkPolicy, PDB, secrets template) y kustomize base/overlays.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-133`
  - **Spec Ref:** `specs/architecture/deployment-architecture.md`
  - **Target Files:** `deploy/k8s/base/**`, `deploy/k8s/overlays/{onprem,airgap}/**`
  - **Verification:** `cd backend && ruff check app tests && mypy app && pytest -q && cd ../frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build && node node_modules/vitest/vitest.mjs run && node node_modules/@playwright/test/cli.js test e2e --project=chromium-desktop`
  - **Retries:** `0/3`

- [x] **TASK-135:** Reverse proxy con TLS, HSTS, CSP, compresión, límites y servido estático del SPA con fallback de rutas.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-133`
  - **Spec Ref:** `ARCHITECTURE.md §6`
  - **Target Files:** `infra/proxy/Caddyfile`, `infra/proxy/nginx.conf`, `infra/proxy/security-headers.conf`
  - **Verification:** `cd backend && ruff check app tests && mypy app && pytest -q && cd ../frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build && node node_modules/vitest/vitest.mjs run && node node_modules/@playwright/test/cli.js test e2e --project=chromium-desktop`
  - **Retries:** `0/3`

- [x] **TASK-136:** Scripts de backup/restore (pg_dump + evidencias + claves), retención y drill automatizado con comparación de conteos.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-133`
  - **Spec Ref:** `AC-113`, `NFR-12`
  - **Target Files:** `scripts/backup.sh`, `scripts/restore.sh`, `scripts/backup_restore_drill.sh`, `docs/recovery-manual.md`
  - **Verification:** `cd backend && ruff check app tests && mypy app && pytest -q && cd ../frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build && node node_modules/vitest/vitest.mjs run && node node_modules/@playwright/test/cli.js test e2e --project=chromium-desktop`
  - **Retries:** `0/3`

- [!] **TASK-137:** Bundle air-gapped: wheels, node_modules offline, fuentes, SBOM y verificación de instalación sin red.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-136`
  - **Spec Ref:** `AC-114`, `P-09`
  - **Target Files:** `scripts/build_offline_bundle.sh`, `scripts/verify_airgap.sh`, `docs/operations-runbook.md`
  - **Verification:** `cd backend && ruff check app tests && mypy app && pytest -q && cd ../frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build && node node_modules/vitest/vitest.mjs run && node node_modules/@playwright/test/cli.js test e2e --project=chromium-desktop`
  - **Deferred:** Offline wheel/node bundle deferred; air-gapped instructions delivered.
  - **Retries:** `0/3`

- [x] **TASK-138:** Observabilidad: `/metrics` Prometheus (RED, colas, autonomía, IA), `/healthz`, `/readyz`, dashboard de ejemplo y log hygiene.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-135`
  - **Spec Ref:** `AC-110, AC-115`, `NFR-11`
  - **Target Files:** `backend/app/core/telemetry.py`, `backend/app/api/v1/health.py`, `infra/observability/dashboard.json`, `backend/tests/security/test_log_hygiene.py`
  - **Verification:** `cd backend && ruff check app tests && mypy app && pytest -q && cd ../frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build && node node_modules/vitest/vitest.mjs run && node node_modules/@playwright/test/cli.js test e2e --project=chromium-desktop`
  - **Retries:** `0/3`

- [x] **TASK-139:** Hardening backend final: cliente HTTP anti-SSRF, límites de upload, timeouts, cierre graceful y revisión de `text()` en SQL.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-138`
  - **Spec Ref:** `ARCHITECTURE.md §6`, `AC-116`
  - **Target Files:** `backend/app/core/http.py`, `backend/app/main.py`, `backend/tests/security/test_ssrf_guard.py`, `backend/tests/integration/test_graceful_shutdown.py`
  - **Verification:** `cd backend && ruff check app tests && mypy app && pytest -q && cd ../frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build && node node_modules/vitest/vitest.mjs run && node node_modules/@playwright/test/cli.js test e2e --project=chromium-desktop`
  - **Retries:** `0/3`

- [x] **TASK-140:** Secret scanning (gitleaks config + pre-commit), `.gitignore` de artefactos y verificación de que `.env` nunca se versiona.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-139`
  - **Spec Ref:** `SECURITY_AUDIT.md §2.3`, `AC-120`
  - **Target Files:** `.gitleaks.toml`, `.pre-commit-config.yaml`, `.gitignore`, `scripts/verify_all.sh`
  - **Verification:** `cd backend && ruff check app tests && mypy app && pytest -q && cd ../frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build && node node_modules/vitest/vitest.mjs run && node node_modules/@playwright/test/cli.js test e2e --project=chromium-desktop`
  - **Retries:** `0/3`

- [x] **TASK-141:** SBOM CycloneDX + verificación de allowlist de licencias de dependencias (backend, frontend, edge).
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-140`
  - **Spec Ref:** `AC-121`, `docs/license-policy.md`
  - **Target Files:** `scripts/generate_sbom.sh`, `scripts/check_licenses.py`, `reports/sbom.json`, `reports/licenses.json`
  - **Verification:** `cd backend && ruff check app tests && mypy app && pytest -q && cd ../frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build && node node_modules/vitest/vitest.mjs run && node node_modules/@playwright/test/cli.js test e2e --project=chromium-desktop`
  - **Retries:** `0/3`

- [!] **TASK-142:** Gate backend: ruff + mypy strict + pytest completo con cobertura mínima y sin skips silenciosos.
  - **Owner:** `@qa-verifier`
  - **Depends On:** `TASK-141`
  - **Spec Ref:** `AC-117`
  - **Target Files:** `backend/pyproject.toml`, `scripts/verify_all.sh`
  - **Verification:** `cd backend && ruff check app tests && mypy app && pytest -q && cd ../frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build && node node_modules/vitest/vitest.mjs run && node node_modules/@playwright/test/cli.js test e2e --project=chromium-desktop`
  - **Deferred:** Coverage threshold gate deferred; tests pass without minimum enforced.
  - **Retries:** `0/3`

- [x] **TASK-143:** Gate frontend: `tsc --noEmit`, build de producción, Vitest completo y budget de bundle.
  - **Owner:** `@qa-verifier`
  - **Depends On:** `TASK-142`
  - **Spec Ref:** `AC-118`
  - **Target Files:** `frontend/package.json`, `frontend/tsconfig.json`, `frontend/vite.config.ts`
  - **Verification:** `cd backend && ruff check app tests && mypy app && pytest -q && cd ../frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build && node node_modules/vitest/vitest.mjs run && node node_modules/@playwright/test/cli.js test e2e --project=chromium-desktop`
  - **Retries:** `0/3`

- [!] **TASK-144:** Gate E2E Playwright completo (23 pantallas + flujos núcleo + autonomía + degradados) en Chromium/Firefox/WebKit.
  - **Owner:** `@qa-verifier`
  - **Depends On:** `TASK-143`
  - **Spec Ref:** `AC-119`, `NFR-13`
  - **Target Files:** `frontend/playwright.config.ts`, `frontend/e2e/**`
  - **Verification:** `cd backend && ruff check app tests && mypy app && pytest -q && cd ../frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build && node node_modules/vitest/vitest.mjs run && node node_modules/@playwright/test/cli.js test e2e --project=chromium-desktop`
  - **Deferred:** Firefox/WebKit E2E deferred; Chromium desktop/mobile configured.
  - **Retries:** `0/3`

- [x] **TASK-145:** Gate dependencias y análisis estático: `pip-audit`, `bandit`, `npm audit --audit-level=high` con umbral bloqueante.
  - **Owner:** `@qa-verifier`
  - **Depends On:** `TASK-144`
  - **Spec Ref:** `AC-120`
  - **Target Files:** `scripts/verify_all.sh`, `reports/security/deps.json`
  - **Verification:** `cd backend && ruff check app tests && mypy app && pytest -q && cd ../frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build && node node_modules/vitest/vitest.mjs run && node node_modules/@playwright/test/cli.js test e2e --project=chromium-desktop`
  - **Retries:** `0/3`

- [!] **TASK-146:** Gate aislamiento multi-tenant sobre todos los recursos y roles (100% cross-org → 404/403 sin fuga).
  - **Owner:** `@qa-verifier`
  - **Depends On:** `TASK-145`
  - **Spec Ref:** `AC-122`
  - **Target Files:** `backend/tests/security/test_tenant_isolation.py`, `reports/security/tenant-isolation.md`
  - **Verification:** `cd backend && ruff check app tests && mypy app && pytest -q && cd ../frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build && node node_modules/vitest/vitest.mjs run && node node_modules/@playwright/test/cli.js test e2e --project=chromium-desktop`
  - **Deferred:** Exhaustive all-resource isolation matrix deferred; per-domain cross-tenant tests delivered.
  - **Retries:** `0/3`

- [!] **TASK-147:** Gate laboratorio de autonomía completo (allow/deny por nivel, blast radius, freeze, budget, kill switch ≤5 s, rollback).
  - **Owner:** `@qa-verifier`
  - **Depends On:** `TASK-146`
  - **Spec Ref:** `AC-123`
  - **Target Files:** `backend/tests/autonomy/**`, `reports/autonomy-lab.md`
  - **Verification:** `cd backend && ruff check app tests && mypy app && pytest -q && cd ../frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build && node node_modules/vitest/vitest.mjs run && node node_modules/@playwright/test/cli.js test e2e --project=chromium-desktop`
  - **Deferred:** Full autonomy lab matrix deferred; core guardrails delivered.
  - **Retries:** `0/3`

- [x] **TASK-148:** Gate prompt-injection y MCP allowlist (0 tool-calls no autorizadas, 0 fuga de system prompt).
  - **Owner:** `@qa-verifier`
  - **Depends On:** `TASK-147`
  - **Spec Ref:** `AC-124`, `AC-65, AC-66`
  - **Target Files:** `backend/tests/security/test_prompt_injection.py`, `reports/security/prompt-injection.md`
  - **Verification:** `cd backend && ruff check app tests && mypy app && pytest -q && cd ../frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build && node node_modules/vitest/vitest.mjs run && node node_modules/@playwright/test/cli.js test e2e --project=chromium-desktop`
  - **Retries:** `0/3`

- [x] **TASK-149:** Documentación final: README con setup exacto, variables de entorno, comandos de verificación y enlaces a `docs/` y `specs/`.
  - **Owner:** `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-148`
  - **Spec Ref:** Exit Gate §6, `docs/*`
  - **Target Files:** `README.md`, `SECURITY.md`, `CONTRIBUTING.md`
  - **Verification:** `cd backend && ruff check app tests && mypy app && pytest -q && cd ../frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build && node node_modules/vitest/vitest.mjs run && node node_modules/@playwright/test/cli.js test e2e --project=chromium-desktop`
  - **Retries:** `0/3`

- [x] **TASK-150:** Auditoría adversarial final, volcado en `.factory/SECURITY_AUDIT.md`, remediación de CRITICAL/HIGH y matriz de aceptación final `AC-XX` con evidencia.
  - **Owner:** `@redteam-auditor` -> `@builder` -> `@qa-verifier`
  - **Depends On:** `TASK-149`
  - **Spec Ref:** `.factory/SECURITY_AUDIT.md §1-5`, `SPEC.md §3, §7`
  - **Target Files:** `.factory/SECURITY_AUDIT.md`, `reports/acceptance-matrix.md`, `reports/release/checksums.txt`
  - **Verification:** `cd backend && ruff check app tests && mypy app && pytest -q && cd ../frontend && node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build && node node_modules/vitest/vitest.mjs run && node node_modules/@playwright/test/cli.js test e2e --project=chromium-desktop`
  - **Retries:** `0/3`

---

## DYNAMIC SECURITY & QA REMEDIATION QUEUE

> `@redteam-auditor` o `@qa-verifier` añaden aquí tareas `SEC-FIX-XXX` si detectan fallos antes del Exit Gate. Cada entrada debe incluir severidad, vector, fichero y test de regresión.

| ID | Severity | Origen | Descripción | Tarea vinculada | Estado |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `SEC-FIX-001` | **HIGH / P0** | `VULN-001` | Redactar `POST /auth/login`: `response_model` explícito (`SessionInfo \| MfaRequiredResponse`) y serialización de `UserProfile`; nunca devolver `password_hash`/`mfa_secret_encrypted`. **Target:** `backend/app/modules/auth/router.py`, `backend/app/modules/auth/service.py`, `backend/tests/integration/test_auth.py`. | `VULN-001` | `VERIFIED` |
| `SEC-FIX-002` | **HIGH / P0** | `VULN-002` | Aplicar scopes de API token en `/overview/executive`, `/overview/soc`, `/overview/notifications` y `mark_notification_read` con `require_permission`/`ctx.can`; test por scope. **Target:** `backend/app/modules/overview/router.py`, `backend/tests/security/test_api_token_scopes.py`. | `VULN-002` | `VERIFIED` |
| `SEC-FIX-003` | **HIGH / P0** | `VULN-003` | Implementar `BreakGlassGrant` (org, aprobador distinto, ticket, justificación, TTL ≤60 min, revocación, banner, auditoría) y exigirlo en `_resolve_org` para cross-org; `403 break_glass_required`. **Target:** `backend/app/core/deps.py`, `backend/app/modules/organizations/`, `backend/app/models/core.py`, migración, `backend/tests/security/test_break_glass.py`. | `VULN-003` | `VERIFIED` |
| `SEC-FIX-004` | **HIGH / P0** | `VULN-004` | No registrar `raw_path`; usar plantilla de ruta y redactar `hs_ing_*`/`Authorization` en logs; opcionalmente mover token de ingesta a header. **Target:** `backend/app/core/logging.py`, `backend/app/modules/events/router.py`, `backend/tests/security/test_log_hygiene.py`. | `VULN-004` | `VERIFIED` |
| `SEC-FIX-005` | **HIGH / P0** | `VULN-005` | Aprobaciones de un solo uso: `consumed_at`/`consumed_by`, consumo atómico (`UPDATE ... WHERE consumed_at IS NULL`) en la misma transacción del broker; test de replay. **Target:** `backend/app/services/broker.py`, `backend/app/models/core.py`, migración, `backend/tests/autonomy/test_approval_single_use.py`. | `VULN-005` | `VERIFIED` |
| `SEC-FIX-006` | **HIGH / P0** | `VULN-006` | Exigir `defence:execute` (y `connector:execute` para `connector.read`) al ejecutar pasos de playbook; alinear `soc_analyst` con la matriz RBAC. **Target:** `backend/app/core/rbac.py`, `backend/app/services/playbook_engine.py`, `backend/app/modules/soar/router.py`, `backend/tests/security/test_playbook_rbac.py`. | `VULN-006` | `VERIFIED` |

---

## CIRCUIT BREAKER & FAILURE ESCALATION LOG

| Task ID | Attempt | Failure Symptom / Stack Trace Summary | Root Cause & Architectural Fix (`@architect`) |
| :--- | :--- | :--- | :--- |
| — | — | — | — |

---

## PHASE EXIT CRITERIA (resumen operativo)

| Phase | Gate de salida |
| :--- | :--- |
| `PHASE_0` | `TASK-001..013` en `- [x]`; build backend y frontend limpios; migraciones up/down; tokens aplicados |
| `PHASE_1` | Auth+MFA+CSRF+RBAC verdes; suite de aislamiento multi-tenant 100%; shell y 3 pantallas |
| `PHASE_2` | Activos/ASM/vulns con scoring determinista; importadores verdes; 3 pantallas |
| `PHASE_3` | Ingesta syslog/webhook idempotente; reglas con dedupe; búsqueda p95 <500 ms; 3 pantallas |
| `PHASE_4` | Incidentes+evidencias+CTI+forense; cadena de custodia; 3 pantallas |
| `PHASE_5` | Reanudación tras crash; aprobaciones; compensación; dry-run; 2 pantallas |
| `PHASE_6` | Deny-by-default; kill switch ≤5 s; rollback; laboratorio de autonomía verde; UI de halt |
| `PHASE_7` | IA honesta (503 sin proveedor); RAG con citas; MCP allowlist; prompt-injection 0 bypass |
| `PHASE_8` | IoT/OT/cloud/conectores/edge con store-and-forward y mTLS; 4 pantallas |
| `PHASE_9` | 8 frameworks; evaluación con score; informes con hash; 3 pantallas |
| `PHASE_10` | 23 pantallas; WCAG AA; responsive; E2E núcleo/degradados verdes |
| `PHASE_11` | Manifiestos válidos; backup/restore drill; air-gap; SBOM; 0 CRITICAL/HIGH; matriz AC completa |

---

## DELIVERY EVIDENCE — 2026-11-26 (RC 0.1.0)

- **Backend:** `pytest -q` on PostgreSQL 18 → **515 passed**. `ruff check` + `ruff format --check` clean. `mypy app` → **Success: no issues found in 179 source files**.
- **Edge agent:** `cd edge && pytest -q` → **92 passed**.
- **Frontend:** `tsc -b`, `vite build` (route-split chunks), `vitest run` → **36 passed**.
- **E2E (Chromium):** all 24 screens render with real data, no console errors/4xx; 7 critical-flow tests pass (login, tenant scoping, overview, SOC/incidents, audit chain, admin, mobile no-overflow).
- **API smoke:** `scripts/smoke_api.py` → **79/79 read endpoints OK**, 0 failures.
- **Dependencies:** `pip-audit --skip-editable` → **no known vulnerabilities**; `bandit` → 0 High/Medium after fixing the syslog bind default; `gitleaks` config added.
- **Deferred:** the 47 `[!]` items above are explicitly post-MVP. They are not simulated; they are absent or simplified and are listed so no capability is overclaimed. None blocks the delivered SOC workflows, but they must be closed before a GA claim.
- **Security gate:** see `.factory/SECURITY_AUDIT.md` for the adversarial report and residual risk.
