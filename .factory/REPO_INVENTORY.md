# REPO INVENTORY — HISPANSHIELD

> **Snapshot histórico (baseline RC1) + apéndice de reconciliación.** Las tablas
> anteriores a la sección “Reconciliation 0.1.2” describen el baseline, no el
> estado actual. Para cifras vigentes ejecutar `python3 scripts/factory_metrics.py`.


- **Repositorio:** `HISPANSHIELD_Autonomous_Cyber_Defense Platform`
- **Snapshot:** 2026-11-26 (árbol de trabajo, no un tag)
- **HEAD git:** `696655b` (`feat: complete SOC platform RC1...`), 3 commits totales
- **Estado del árbol:** **sucio y en cambio activo**. Al inicio del snapshot: 14 modificados + 2 sin seguimiento (`backend/migrations/versions/0007_edge_fingerprint_scope.py`, `backend/tests/security/test_bootstrap.py`). Durante la inspección el diff creció a **24 archivos / +509 −89**, incluyendo `Dockerfile`, `core/config.py`, `core/ssrf.py`, `ai/common.py`, `ai/providers.py`, `llm/*`, `scripts/backup.sh` y `scripts/restore.sh` (remediación de VULN-008/009/020/028 y hardening). Los conteos y números de línea reflejan el instante de lectura; pueden variar en el siguiente commit.
- **Método:** lectura estática, `find`/`wc`, AST de Python para rutas y `pytest --collect-only` sin escritura de caché. No se ejecutaron tests contra PostgreSQL ni se modificó código de aplicación.

---

## 1. STACK Y VERSIONES REALES

### 1.1 Backend (`backend/pyproject.toml`)

| Componente | Versión pinneada | Evidencia |
| :--- | :--- | :--- |
| Python | `>=3.12` | `backend/pyproject.toml:5` |
| FastAPI | `0.165.0` | `backend/pyproject.toml:7` |
| Uvicorn | `0.34.2` | `backend/pyproject.toml:8` |
| Starlette | `1.10.0` | `backend/pyproject.toml:9` |
| SQLAlchemy | `2.0.41` (sync) | `backend/pyproject.toml:10`; `backend/app/core/db.py:20-29` |
| psycopg | `3.2.9` (binary) | `backend/pyproject.toml:11` |
| Alembic | `1.15.2` | `backend/pyproject.toml:12` |
| Pydantic / settings | `2.11.5` / `2.9.1` | `backend/pyproject.toml:13-14` |
| argon2-cffi / pyotp | `25.1.0` / `2.9.0` | `backend/pyproject.toml:16-17` |
| cryptography (Fernet) | `50.0.0` | `backend/pyproject.toml:18` |
| httpx | `0.28.1` | `backend/pyproject.toml:19` |
| numpy | `2.2.6` | `backend/pyproject.toml:22` |
| Jinja2 | `3.1.6` | `backend/pyproject.toml:23` |
| Prometheus client | `0.21.1` | `backend/pyproject.toml:25` |
| Test/calidad | pytest `9.0.3`, ruff `0.11.10`, mypy `1.15.0`, bandit `1.8.3`, pip-audit `2.9.0` | `backend/pyproject.toml:29-38` |

> Nota: `.factory/ARCHITECTURE.md:17-25` declara FastAPI `^0.115`, cryptography `^44`, numpy `^2.1`, pytest `^8`. Los pins reales difieren (ver §15).

### 1.2 Frontend (`frontend/package.json`)

| Componente | Versión | Evidencia |
| :--- | :--- | :--- |
| React / React DOM | `^19.0.0` | `frontend/package.json:15-16` |
| react-router-dom | `^7.1.1` | `frontend/package.json:17` |
| @tanstack/react-query | `^5.62.7` | `frontend/package.json:12` |
| Vite | `^6.0.5` | `frontend/package.json:34` |
| TypeScript | `^5.7.2` | `frontend/package.json:33` |
| Vitest / Testing Library | `^5.1.2` / `^16.1.0` | `frontend/package.json:35,27` |
| Playwright | `^1.49.1` | `frontend/package.json:25` |
| lucide-react | `^0.468.0` | `frontend/package.json:14` |

Sin Tailwind, sin librería de componentes, **sin `uplot`** y **sin `axe-core`** (contradice `.factory/ARCHITECTURE.md:32-33`).

### 1.3 Edge (`edge/pyproject.toml`)

- Python `>=3.12`; única dependencia `httpx>=0.28,<0.29` (`edge/pyproject.toml:7`).
- Cola durable SQLite WAL nativa (`edge/hispanshield_edge/queue.py`), firma HMAC (`edge/hispanshield_edge/client.py:104-114`), TLS/mTLS opcional por certificado de cliente (`client.py:230-240`).
- Entrypoint `hispanshield-edge` (`edge/pyproject.toml:11`).

### 1.4 Datos y despliegue

- PostgreSQL **18**: `deploy/compose/docker-compose.yml:5` (`postgres:18-alpine`), `.github/workflows/ci.yml:21` (`postgres:18`), tests contra PostgreSQL real (`backend/tests/conftest.py`).
- Imagen única multi-stage: build Node 22, runtime `python:3.12-slim`, usuario 10001, `uvicorn ... --workers ${HS_WORKERS:-2}` (`Dockerfile:4-44`).
- Compose: `postgres`, `app`, `ollama` (perfil `ai`) (`deploy/compose/docker-compose.yml:3-61`).
- Kubernetes: 11 objetos en `deploy/k8s/manifests.yaml` (Namespace, ConfigMap, Secret, PVC, Job de migración, Deployment 2 réplicas, Service, PDB, HPA, NetworkPolicy, Ingress).

---

## 2. CONTEO DE ARCHIVOS Y LÍNEAS POR ÁREA

Excluye `node_modules/`, `__pycache__/`, `.mypy_cache/`, `.pytest_cache/`, `.ruff_cache/`, `.pyc`, `.map`, `.git/`.

| Área | Ficheros | Líneas | Comentario |
| :--- | ---: | ---: | :--- |
| `backend/app` | 190 | 48.804 | 179 módulos Python + 10 YAML de frameworks + datos |
| `backend/app/core` | 11 | 1.530 | config, db, crypto, deps, rbac, audit, rate_limit, ssrf, errors, logging, schemas |
| `backend/app/models` | 10 | 1.601 | 59 tablas declaradas |
| `backend/app/modules` | 107 | 28.374 | 23 dominios autodescubiertos |
| `backend/app/services` | 46 | 11.949 | motores, conectores, LLM, RAG, broker |
| `backend/app/workers` | 2 | 307 | solo `syslog_receiver` |
| `backend/app/api` | 1 | 50 | autodescubrimiento |
| `backend/migrations` | 9 | 1.644 | 7 revisiones + `env.py` + plantilla |
| `backend/tests` | 38 | 13.414 | 37 ficheros de test + conftest |
| `backend/scripts` | 10 | 1.143 | workers y seeds |
| `edge/hispanshield_edge` | 8 | 3.336 | agente, cliente, cola, colectores, CLI |
| `edge/tests` | 9 | 1.844 | 7 ficheros de test + fake core |
| `frontend/src` | 57 | 43.782 | 28 páginas + 5 tests de página |
| `frontend/src/pages` | 33 | 35.029 | 28 `.tsx` + 5 tests |
| `frontend/src/components` | 13 | 4.769 | UI kit, layout, features |
| `frontend/src/lib` | 5 | 1.120 | api, auth, i18n, query, format |
| `frontend/src/styles` | 2 | 2.682 | `app.css`, `fonts.css` |
| `deploy` | 2 | 332 | compose + k8s |
| `docs` | 29 | 10.415 | 28 `.md` + OpenAPI estático + 6 PNG |
| `specs` | 57 | 8.415 | 12 ADR + 15 dominios + arquitectura + testing |
| `scripts` | 9 | 462 | bootstrap, backup/restore, SBOM, smoke |
| `.github` | 1 | 134 | un workflow CI |
| `.factory` | 4 | 3.292 | SPEC/ARCHITECTURE/TASKS/SECURITY_AUDIT |
| `infra/` | **0** | **0** | declarado en arquitectura, vacío |
| `tests/` (raíz) | 1 | 39 | solo `README.md` |
| `examples/` | **0** | **0** | vacío |
| `reports/` | **0** | **0** | vacío |
| Python total (backend+edge+scripts) | 255 | 67.077 | — |

---

## 3. ÁRBOL RESUMIDO

```text
backend/
  app/
    main.py                 # create_app, middleware, error handlers, health, metrics, SPA fallback
    api/router.py           # importa app.modules.<x>.router automáticamente
    core/                   # 11 módulos transversales
    models/                 # core, assets, events, incidents, ti, connectors, ai, compliance, edge
    modules/<dominio>/      # 23 paquetes: router/schemas/service (+aux)
    services/               # detection, broker, policy, playbook_engine, actions, risk, RAG, LLM, conectores
    workers/syslog_receiver.py
    data/frameworks/*.yaml  # 10 marcos, 105 controles
    seed.py                 # 1.682 líneas de datos demo
  migrations/versions/      # 6 revisiones + 0007 sin seguimiento
  scripts/                  # connector_worker, playbook_worker, run_syslog, seeds, evaluación
  tests/{unit,integration,security}
edge/hispanshield_edge/     # agente store-and-forward
frontend/src/               # App.tsx, pages, components, lib, styles
deploy/{compose,k8s}
docs/, specs/, scripts/, .github/workflows/ci.yml
infra/ (vacío), examples/ (vacío), reports/ (vacío), tests/ (solo README)
```

### 3.1 Directorios declarados y inexistentes/vacíos

- `backend/app/schemas/` existe pero **0 archivos** (los contratos viven en `modules/*/schemas.py` y `core/schemas.py`).
- `backend/app/modules/*/repository.py`: **0 archivos** en todo el repo (declarado en `.factory/ARCHITECTURE.md:80,124` y regla M-03).
- `frontend/src/styles/tokens.css`: no existe; los tokens están en `:root` de `frontend/src/styles/app.css:1`.
- `frontend/src/lib/sse.ts`, `frontend/src/types/`, `frontend/src/components/charts/`, `frontend/src/routes.tsx`: no existen (declarados en `ARCHITECTURE.md:94-98`).
- `frontend/src/pages/Mfa.tsx`, `Setup.tsx`: no existen; el MFA se resuelve inline en `frontend/src/pages/Login.tsx:18-65,110-117`.
- `backend/tests/autonomy/`, `backend/tests/performance/`: no existen; `specs/testing/strategy.md:96` referencia `tests/autonomy/` y `:97` `tests/security/test_prompt_injection.py` (ausente).
- `infra/`, `examples/`, `reports/`: vacíos, aunque CI/SBOM/arquitectura los mencionan.

---

## 4. TOPOLOGÍA BACKEND REAL

### 4.1 `app/main.py` (231 líneas)

- Middlewares en orden: `MetricsMiddleware`, `BodySizeLimitMiddleware`, `SecurityHeadersMiddleware`, `RequestContextMiddleware`, `OriginCheckMiddleware`, CORS condicional (`main.py:113-127`).
- Handlers normalizados: `AppError`, `RequestValidationError`, `HTTPException`, `Exception` (`main.py:129-165`).
- Lifespan **solo** configura logging y valida settings; **no arranca workers ni tareas de fondo** (`main.py:93-99`).
- Monta `api_router` con prefijo `/api/v1` (`main.py:167`).
- Operativos: `GET /healthz`, `GET /readyz` (solo `SELECT 1`), `GET /metrics` (token opcional) (`main.py:169-192`).
- SPA: sirve `frontend/dist`, `StaticFiles` en `/static` y fallback `GET /{full_path}` (`main.py:198-224`).
- Docs: `/api/docs`, `/api/redoc`, `/api/openapi.json` **fuera** del prefijo `/api/v1` (`main.py:107-109`).

### 4.2 Autodescubrimiento (`app/api/router.py`, 50 líneas)

- Recorre `app.modules`, importa `<m>.router` y monta el objeto `router` (`router.py:24-45`).
- Expone `GET /api/v1/meta/domains` (`router.py:48-50`).
- **23 dominios montados**: agents, ai, assets, attack_surface, auth, compliance, connectors, defence, edge, events, forensics, incidents, iot, mcp, organizations, ot, overview, posture, reports, siem, soar, threat_intel, vulnerabilities.

### 4.3 Módulos sin `service.py`

`agents`, `ai`, `organizations`, `overview`, `soar`. Algunos concentran lógica en el router:
- `overview/router.py` 455 líneas con SQL directo (p. ej. búsqueda global `overview/router.py:319-404`).
- `organizations/router.py` 501 líneas con queries/validación inline.
- `soar/router.py` 570 líneas; la ejecución vive en `app/services/playbook_engine.py` (1.312 líneas).
- `agents/router.py` 290 líneas; catálogo/seed en `modules/agents/catalog.py`, `seed.py`.

### 4.4 Dependencias cruzadas reales entre módulos

| Importador | Importado | Evidencia |
| :--- | :--- | :--- |
| `iot/router.py` | `assets.service.ensure_zone_exists` | `modules/iot/router.py:18` |
| `ot/router.py` | `assets.service.ensure_zone_exists` | `modules/ot/router.py:20` |
| `attack_surface/service.py` | `assets.service.asset_public_ip` | `modules/attack_surface/service.py:17` |
| `organizations/router.py` | `auth.service.user_organizations` | `modules/organizations/router.py:19` |
| `iot/schemas.py`, `ot/schemas.py`, `vulnerabilities/schemas.py` | `assets.schemas` | líneas 13 de cada fichero |
| `services/playbook_engine.py` | `defence.service`, `incidents.service`, `soar.validation` | `services/playbook_engine.py:43-50` |

Esto contradice la regla “un módulo no importa el service de otro” (`.factory/ARCHITECTURE.md:46,136`).

---

## 5. INVENTARIO DE ENDPOINTS (284 operaciones)

Calculado por AST sobre `backend/app/modules/**/*.py`; prefijo global `/api/v1`. Distribución por método: **GET 127, POST 111, PATCH 25, DELETE 20, PUT 1**. Rutas únicas: **215**. Más `GET /api/v1/meta/domains` y los operativos `/healthz`, `/readyz`, `/metrics`.

| Módulo | Ops | Prefijo |
| :--- | ---: | :--- |
| ai | 26 | `/ai` + subrouters |
| threat_intel | 23 | `/threat-intel` |
| assets | 20 | `/assets` (14) + `/zones` (6) |
| organizations | 19 | `/organizations` |
| siem | 17 | `/siem` |
| events | 16 | sin prefijo (`/events`, `/ingest-sources`, `/ingest/{token}`) |
| auth | 15 | `/auth` |
| soar | 15 | `/soar` |
| mcp | 13 | `/mcp` |
| attack_surface | 12 | `/attack-surface` |
| connectors | 12 | `/connectors` |
| edge | 12 | `/edge` |
| compliance | 11 | `/compliance` |
| defence | 11 | `/defence` |
| incidents | 11 | `/incidents` |
| vulnerabilities | 10 | `/vulnerabilities` |
| agents | 7 | `/agents` |
| forensics | 7 | `/forensics` |
| iot | 7 | `/iot` |
| ot | 6 | `/ot` |
| overview | 5 | `/overview` |
| reports | 5 | `/reports` |
| posture | 4 | `/posture` |
| **Total** | **284** | — |

### 5.1 auth (15)

```
POST   /auth/login
POST   /auth/mfa/verify
POST   /auth/logout
GET    /auth/me
POST   /auth/switch-org
POST   /auth/break-glass
POST   /auth/break-glass/{grant_id}/revoke
POST   /auth/change-password
POST   /auth/mfa/enroll
POST   /auth/mfa/activate
POST   /auth/mfa/disable
GET    /auth/api-tokens
POST   /auth/api-tokens
DELETE /auth/api-tokens/{token_id}
GET    /auth/permissions
```

### 5.2 organizations (19)

```
GET    /organizations
POST   /organizations
GET    /organizations/current
PATCH  /organizations/current
GET    /organizations/current/members
POST   /organizations/current/members
PATCH  /organizations/current/members/{membership_id}
DELETE /organizations/current/members/{membership_id}
GET    /organizations/current/policies
POST   /organizations/current/policies
PATCH  /organizations/current/policies/{policy_id}
GET    /organizations/current/kill-switches
POST   /organizations/current/kill-switches
POST   /organizations/current/kill-switches/{switch_id}/release
GET    /organizations/current/approvals
POST   /organizations/current/approvals/{approval_id}/decision
GET    /organizations/current/audit
GET    /organizations/current/audit/verify
GET    /organizations/{org_id}
```

### 5.3 assets + zones (20)

```
GET    /assets
POST   /assets
POST   /assets/import
GET    /assets/{asset_id}
PATCH  /assets/{asset_id}
DELETE /assets/{asset_id}
GET    /assets/{asset_id}/identities
POST   /assets/{asset_id}/identities
DELETE /assets/{asset_id}/identities/{identity_id}
GET    /assets/{asset_id}/relationships
POST   /assets/{asset_id}/relationships
DELETE /assets/relationships/{relationship_id}
GET    /assets/{asset_id}/graph
GET    /assets/{asset_id}/vulnerabilities
GET    /zones
POST   /zones
GET    /zones/{zone_id}
PATCH  /zones/{zone_id}
DELETE /zones/{zone_id}
GET    /zones/{zone_id}/assets
```

### 5.4 vulnerabilities (10)

```
GET    /vulnerabilities
POST   /vulnerabilities
POST   /vulnerabilities/import/cve
POST   /vulnerabilities/import/kev
POST   /vulnerabilities/import/epss
GET    /vulnerabilities/summary
GET    /vulnerabilities/{vulnerability_id}
PATCH  /vulnerabilities/{vulnerability_id}
DELETE /vulnerabilities/{vulnerability_id}
POST   /vulnerabilities/{vulnerability_id}/recalculate
```

### 5.5 attack-surface (12)

```
GET    /attack-surface/findings
POST   /attack-surface/findings
GET    /attack-surface/findings/{finding_id}
PATCH  /attack-surface/findings/{finding_id}
POST   /attack-surface/analyze
GET    /attack-surface/summary
GET    /attack-surface/discovery-jobs
POST   /attack-surface/discovery-jobs
GET    /attack-surface/discovery-jobs/{job_id}
PATCH  /attack-surface/discovery-jobs/{job_id}
DELETE /attack-surface/discovery-jobs/{job_id}
POST   /attack-surface/discovery-jobs/{job_id}/run
```

### 5.6 events (16)

```
GET    /ingest-sources
POST   /ingest-sources
GET    /ingest-sources/{source_id}
PATCH  /ingest-sources/{source_id}
DELETE /ingest-sources/{source_id}
POST   /ingest-sources/{source_id}/enable
POST   /ingest-sources/{source_id}/disable
POST   /ingest-sources/{source_id}/rotate-token
POST   /ingest/{source_token}
POST   /events/ingest
GET    /events/stats
GET    /events/retention
PUT    /events/retention
POST   /events/retention/purge
GET    /events
GET    /events/{event_id}
```

### 5.7 siem (17)

```
GET    /siem/rules/templates
POST   /siem/rules/import
GET    /siem/rules
POST   /siem/rules
GET    /siem/rules/{rule_id}
PATCH  /siem/rules/{rule_id}
DELETE /siem/rules/{rule_id}
POST   /siem/rules/{rule_id}/enable
POST   /siem/rules/{rule_id}/disable
POST   /siem/rules/{rule_id}/test
GET    /siem/mitre/coverage
GET    /siem/alerts/stats
POST   /siem/alerts/bulk
GET    /siem/alerts
GET    /siem/alerts/{alert_id}
PATCH  /siem/alerts/{alert_id}
POST   /siem/alerts/{alert_id}/promote
```

### 5.8 incidents (11)

```
GET    /incidents/metrics
GET    /incidents
POST   /incidents
GET    /incidents/{incident_id}
PATCH  /incidents/{incident_id}
POST   /incidents/{incident_id}/status
GET    /incidents/{incident_id}/timeline
POST   /incidents/{incident_id}/timeline
POST   /incidents/{incident_id}/evidence
GET    /incidents/evidence/{evidence_id}/download
POST   /incidents/evidence/{evidence_id}/seal
```

### 5.9 threat-intel (23)

```
GET/POST        /threat-intel/indicators
GET/PATCH/DELETE /threat-intel/indicators/{indicator_id}
POST            /threat-intel/indicators/{indicator_id}/deactivate
POST            /threat-intel/indicators/import
POST            /threat-intel/indicators/import/csv
GET/POST        /threat-intel/actors
GET/PATCH/DELETE /threat-intel/actors/{actor_id}
GET/POST        /threat-intel/feeds
GET/PATCH/DELETE /threat-intel/feeds/{feed_id}
POST            /threat-intel/feeds/{feed_id}/sync
GET             /threat-intel/enrich
GET             /threat-intel/mitre/techniques
GET             /threat-intel/mitre/coverage
GET             /threat-intel/summary
```

### 5.10 soar (15)

```
GET    /soar/playbooks
POST   /soar/playbooks
POST   /soar/playbooks/validate
GET    /soar/playbooks/{playbook_id}
PATCH  /soar/playbooks/{playbook_id}
POST   /soar/playbooks/{playbook_id}/validate
POST   /soar/playbooks/{playbook_id}/simulate
POST   /soar/playbooks/{playbook_id}/publish
POST   /soar/playbooks/{playbook_id}/archive
POST   /soar/playbooks/{playbook_id}/execute
GET    /soar/executions
POST   /soar/executions
GET    /soar/executions/{execution_id}
GET    /soar/executions/{execution_id}/steps
POST   /soar/executions/{execution_id}/resume
```

### 5.11 defence (11)

```
GET    /defence/actions
POST   /defence/evaluate
POST   /defence/simulate
POST   /defence/execute
GET    /defence/remediations
GET    /defence/remediations/{remediation_id}
POST   /defence/remediations/{remediation_id}/execute
POST   /defence/remediations/{remediation_id}/rollback
POST   /defence/remediations/{remediation_id}/verify
GET    /defence/kill-switches/effective
GET    /defence/policy/snapshot
```

### 5.12 agents (7)

```
GET    /agents
GET    /agents/runs
GET    /agents/runs/{run_id}
POST   /agents/runs/{run_id}/cancel
POST   /agents/chat
GET    /agents/{code}
POST   /agents/{code}/runs
```

### 5.13 ai (26)

```
GET/POST          /ai/providers
GET/PATCH/DELETE  /ai/providers/{provider_id}
POST              /ai/providers/{provider_id}/health
POST              /ai/providers/{provider_id}/test
POST              /ai/providers/{provider_id}/discover
GET               /ai/providers/{provider_id}/models
GET/POST          /ai/models
GET/PATCH/DELETE  /ai/models/{model_id}
POST              /ai/models/{model_id}/evaluate
GET               /ai/models/{model_id}/evaluations
POST              /ai/complete
POST              /ai/embeddings
GET/POST          /ai/knowledge
GET/PATCH/DELETE  /ai/knowledge/{document_id}
POST              /ai/knowledge/search
GET               /ai/usage
GET               /ai/health
```

### 5.14 connectors (12)

```
GET    /connectors/catalog
GET    /connectors/health/summary
GET    /connectors
POST   /connectors
GET    /connectors/{connector_id}
GET    /connectors/{connector_id}/health
PATCH  /connectors/{connector_id}
DELETE /connectors/{connector_id}
POST   /connectors/{connector_id}/health
POST   /connectors/{connector_id}/invoke/{capability}
POST   /connectors/{connector_id}/sync
GET    /connectors/{connector_id}/runs
```

### 5.15 edge (12)

```
POST   /edge/gateways/enroll-token
POST   /edge/gateways/register
POST   /edge/gateways/{gateway_id}/heartbeat
POST   /edge/gateways/{gateway_id}/events
GET    /edge/gateways
GET    /edge/gateways/{gateway_id}
PATCH  /edge/gateways/{gateway_id}
POST   /edge/gateways/{gateway_id}/revoke
POST   /edge/gateways/{gateway_id}/rotate-key
GET    /edge/gateways/{gateway_id}/config-bundle/signed
GET    /edge/gateways/{gateway_id}/config-bundle
GET    /edge/gateways/{gateway_id}/events
```

### 5.16 mcp (13)

```
GET/POST          /mcp/servers
GET/PATCH/DELETE  /mcp/servers/{server_id}
POST              /mcp/servers/{server_id}/discover
POST              /mcp/servers/{server_id}/approve
GET               /mcp/servers/{server_id}/tools
GET               /mcp/tools
GET               /mcp/tools/{tool_id}
POST              /mcp/tools/{tool_id}/approve
POST              /mcp/tools/{tool_id}/execute
GET               /mcp/tools/{tool_id}/executions
```

### 5.17 iot (7) / ot (6)

```
GET    /iot/devices
POST   /iot/devices
PATCH  /iot/devices/{asset_id}
DELETE /iot/devices/{asset_id}
POST   /iot/telemetry
GET    /iot/protocols
GET    /iot/summary

GET    /ot/devices
POST   /ot/devices
PATCH  /ot/devices/{asset_id}
GET    /ot/protocols
POST   /ot/telemetry
GET    /ot/posture
```

### 5.18 compliance (11)

```
GET    /compliance/frameworks
GET    /compliance/frameworks/{code}/versions
POST   /compliance/frameworks/import
GET    /compliance/frameworks/{identifier}
POST   /compliance/assessments
GET    /compliance/assessments
GET    /compliance/assessments/{assessment_id}
PATCH  /compliance/assessments/{assessment_id}/controls/{control_status_id}
POST   /compliance/assessments/{assessment_id}/complete
GET    /compliance/assessments/{assessment_id}/gap-analysis
GET    /compliance/summary
```

### 5.19 forensics (7) / reports (5) / overview (5) / posture (4)

```
GET    /forensics/cases
GET    /forensics/cases/{incident_id}
POST   /forensics/cases/{incident_id}/export
GET    /forensics/evidence
POST   /forensics/evidence/{evidence_id}/verify-hash
GET    /forensics/evidence/{evidence_id}/chain-of-custody
GET    /forensics/timeline/export

POST   /reports/generate
GET    /reports
GET    /reports/{report_id}
GET    /reports/{report_id}/download
DELETE /reports/{report_id}

GET    /overview/executive
GET    /overview/soc
GET    /overview/search
GET    /overview/notifications
POST   /overview/notifications/{notification_id}/read

GET    /posture/network
GET    /posture/cloud
GET    /posture/identity
GET    /posture/summary
```

---

## 6. MODELOS Y TABLAS (59)

`backend/app/models/__init__.py:3-59` importa todos los modelos para Alembic. Todos los `id` son UUID salvo `security_events` (BIGINT autoincremental, `models/events.py:58`).

| Fichero | Tablas |
| :--- | :--- |
| `core.py` (251 líneas) | `organizations`, `users`, `memberships`, `sessions`, `api_tokens`, `audit_records`, `rate_limit_buckets`, `kill_switches`, `policies`, `approvals`, `break_glass_grants`, `notifications` |
| `assets.py` (257) | `zones`, `assets`, `asset_identities`, `asset_relationships`, `iot_devices`, `ot_devices`, `cve_catalog`, `vulnerabilities`, `attack_surface_findings`, `discovery_jobs` |
| `events.py` (148) | `ingest_sources`, `security_events`, `detection_rules`, `alerts` |
| `incidents.py` (195) | `incidents`, `incident_timeline`, `evidence`, `playbooks`, `playbook_executions`, `playbook_steps`, `remediations` |
| `ti.py` (81) | `threat_actors`, `threat_indicators`, `ti_feeds` |
| `connectors.py` (149) | `connectors`, `connector_runs`, `connector_errors`, `mcp_servers`, `mcp_tools`, `tool_executions` |
| `ai.py` (183) | `ai_providers`, `ai_models`, `ai_invocations`, `knowledge_documents`, `knowledge_chunks`, `agents`, `agent_runs`, `agent_messages` |
| `compliance.py` (145) | `compliance_frameworks`, `compliance_controls`, `compliance_assessments`, `compliance_control_status`, `reports`, `control_evidence_links` |
| `edge.py` (71) | `edge_gateways`, `edge_ingest_events`, `edge_sync_cursors` |

Observaciones de esquema:
- `assets` **no** tiene `deleted_at`; solo `organizations.deleted_at` (`models/core.py:39`). No hay soft delete/restore de activos.
- `knowledge_chunks.embedding` es **JSONB** `list[float]` (`models/ai.py:111`), no `pgvector`.
- No existen tablas `jobs`, `outbox_events`, `invitations`, `exposure_diffs`, `risk_exceptions`, `campaigns`, `playbook_versions`, `policy_decisions`, `action_results`, `legal_hold` (declaradas en `.factory/ARCHITECTURE.md:279,377-381`).
- `detection_rules.version` y `playbooks.version` son enteros, sin tabla de versiones/histórico (`models/events.py:108`, `models/incidents.py:102`).

---

## 7. MIGRACIONES ALEMBIC (7 revisiones)

Cadena: `83825cd958ca → 0002_hardening → 0003_audit_truncate → 0004_approval_single_use → 0005_break_glass → 0006_break_glass_ticket → 0007_edge_fingerprint_scope`.

| Revisión | Líneas | Contenido |
| :--- | ---: | :--- |
| `83825cd958ca_initial_schema.py` | 1.374 | 58 tablas + índices |
| `0002_hardening.py` | 62 | trigger append-only de auditoría, índice GIN FTS `ix_events_fts`, índices de eventos/incidentes |
| `0003_audit_truncate_guard.py` | 26 | trigger que bloquea `TRUNCATE` en auditoría |
| `0004_approval_single_use.py` | 21 | `approvals.consumed_at` |
| `0005_break_glass.py` | 34 | tabla `break_glass_grants` |
| `0006_break_glass_ticket.py` | 23 | columna `ticket` + backfill `legacy-migration` |
| `0007_edge_fingerprint_scope.py` | 29 | **sin seguimiento git**: fingerprint único pasa a `(org_id, fingerprint)` (VULN-028) |

Integridad modelo↔migración: 59 tablas de modelo = 58 iniciales + `break_glass_grants`; sin tablas huérfanas.

Carencias respecto a specs:
- `security_events` **no está particionada** (tabla única en la migración inicial).
- El índice FTS existe (`0002_hardening.py:37-53`) pero las consultas usan `LIKE` (ver §15).
- No hay migración de `outbox_events`, `jobs`, `invitations`.

---

## 8. SERVICIOS Y WORKERS REALES

### 8.1 Servicios (`backend/app/services`)

| Fichero | Líneas | Función |
| :--- | ---: | :--- |
| `playbook_engine.py` | 1.312 | ejecución durable, claim `FOR UPDATE SKIP LOCKED`, reintentos/backoff, compensación, resume |
| `normalization/parsers.py` | 1.291 | JSON/CEF/LEEF/syslog/OCSF |
| `connectors/normalize.py` | 954 | mapeo de conectores a OCSF |
| `detection.py` | 948 | DSL, match, dedupe, correlación, alertas |
| `agents/orchestrator.py` | 800 | runs de agentes, tool-calls |
| `normalization/ocsf.py` | 627 | esquema OCSF |
| `llm/router.py` | 525 | routing, health, embeddings, semáforo por proceso |
| `broker.py` | 348 | única vía de acción: re-evalúa política, aprobaciones, kill switch, ejecuta adaptador |
| `agents/tools.py` | 332 | herramientas allowlisted |
| `policy_engine.py` | 296 | niveles A0–A4, deny-by-default |
| `forensic_evidence.py` | 280 | hash/cadena de custodia |
| `risk.py` | 256 | scoring de vulnerabilidades |
| `connectors/base.py` | 205 | registro de adaptadores y capacidades |
| `actions.py` | 192 | 13 acciones canónicas (4×A1, 1×A2, 8×A3, **0×A4**) |
| `llm/safety.py` | 191 | anti prompt-injection, redacción |
| `rag/*` | ~350 | chunking, embeddings hash, retrieval, ingest |
| `connectors/runtime.py` | ~150 | descifrado, instancia de adaptador, circuit breaker en proceso |
| `bootstrap.py` | 138 | bootstrap de admin |

### 8.2 Workers / entrypoints (4 reales, ninguno autoarrancado por la API)

| Entrypoint | Tipo | Evidencia |
| :--- | :--- | :--- |
| `backend/scripts/playbook_worker.py` | proceso SOAR | `--once`/loop; `worker_run_once` |
| `backend/scripts/connector_worker.py` | health + sync de conectores | `--once`/`--loop` |
| `backend/scripts/run_syslog.py` | listener UDP/TCP syslog | opt-in, `HS_SYSLOG_TOKEN`, bind loopback por defecto |
| `backend/app/workers/syslog_receiver.py` | librería asyncio | 307 líneas; no arranca al importar |

No existen workers de scheduler, ingesta, detección ni IA. La detección se ejecuta **síncronamente dentro de la transacción de ingesta** (`modules/events/service.py:318-340`).

---

## 9. CONECTORES: IMPLEMENTADO VS DECLARADO

### 9.1 Adaptadores reales (12)

`backend/app/services/connectors/adapters/__init__.py:10-38` registra 12 módulos.

| Adaptador | Tipo | Capacidades |
| :--- | :--- | :--- |
| Wazuh | `wazuh` | `read_alerts`, `read_agents`, `active_response`, `isolate_endpoint`, `unisolate_endpoint` |
| Elastic Security | `elastic_security` | `read_alerts` |
| Microsoft Sentinel | `microsoft_sentinel` | `read_alerts` |
| Microsoft Defender | `microsoft_defender` | `read_alerts`, `isolate_endpoint`, `unisolate_endpoint` |
| MISP | `misp` | `read_indicators` |
| OpenCTI | `opencti` | `read_indicators` |
| Suricata file | `suricata_file` | `read_alerts` |
| Zeek file | `zeek_file` | `read_alerts` |
| Keycloak | `keycloak` | `read_users`, `read_sessions`, `disable_user`, `enable_user`, `revoke_sessions` |
| pfSense | `pfsense` | `block_ip`, `unblock_ip` |
| OPNsense | `opnsense` | `block_ip`, `unblock_ip` |
| Generic webhook | `generic_webhook` | `notify_webhook` |

Total: 22 capacidades. Todos los adaptadores tienen `health_check` + `invoke`; los de fichero validan ruta absoluta y traversal (`adapters/_support.py:180-198`).

### 9.2 Acciones vs capacidades (puntos muertos)

`backend/app/services/actions.py` define 13 acciones. Dos exigen capacidades que **ningún adaptador implementa**:

| Acción | Capacidad exigida | Adaptador que la implementa |
| :--- | :--- | :--- |
| `configuration.restore` (`actions.py:145`) | `restore_configuration` | **ninguno** |
| `patch.apply` (`actions.py:156`) | `apply_patch` | **ninguno** |

El broker fallará con `ServiceUnavailable("No installed connector adapter supports this capability")` (`services/connectors/runtime.py:107-118`).

### 9.3 Declarado y no implementado

| Declaración | Evidencia | Realidad |
| :--- | :--- | :--- |
| AWS/Azure/GCP CSPM read-only “supported” | `docs/compatibility-matrix.md:83-85`; `specs/integrations/compatibility-matrix.md:99-104`; `specs/domains/cloud.md:6,57-60` | No hay módulo `cloud`, ni tablas, ni endpoints `/cloud/*`, ni adaptadores. `Cloud.tsx` consume `GET /posture/cloud` derivado de inventario (`frontend/src/pages/Cloud.tsx:243`) |
| `cloud_audit_pull` | `specs/integrations/protocol-registry.md:44` | Ausente |
| `splunk_hec` | `protocol-registry.md:48`; `docs/compatibility-matrix.md:61` | Sin adaptador Splunk |
| `edr_api` (`host.isolate`, `file.quarantine`) | `protocol-registry.md:63` | Solo Defender/Wazuh isolate; no `file.quarantine` |
| `ticketing_api`, `email_smtp` | `protocol-registry.md:65-66` | Sin adaptadores de ticketing ni SMTP |
| CrowdStrike, SentinelOne, Palo Alto, Fortinet, Cisco, QRadar, Splunk, Shuffle, XSOAR | `README.md:270-274` | No existen como adaptadores |
| Importadores Nessus/OpenVAS/Trivy | `docs/compatibility-matrix.md:122-124`; `.factory/SPEC.md:212` | Solo import JSON CVE/KEV/EPSS (`modules/vulnerabilities/router.py:93-149`) |
| Recovery codes MFA | `docs/compatibility-matrix.md:109`; `specs/domains/identity.md:26` | `grep -ri recovery` = 0 en backend; solo TOTP |
| SSE `/events/stream` | `.factory/ARCHITECTURE.md:321,462`; `specs/domains/siem.md:88` | Sin endpoint, sin `EventSource` en frontend; solo polling (`refetchInterval`) |

---

## 10. IA, AGENTES Y DETECCIÓN

- **Proveedores permitidos**: `ollama|vllm|llamacpp|openai_compatible` (`modules/ai/schemas.py:13`). Clientes: `OllamaClient` y `OpenAICompatibleClient` (`services/llm/router.py:27-33,81-86`). Sin cliente Anthropic nativo (aunque la matriz lo marca “experimental”).
- **Agentes**: 16 en catálogo (`modules/agents/catalog.py`): `soc_master`, `siem_analyst`, `threat_intel_analyst`, `incident_responder`, `vulnerability_manager`, `attack_surface_analyst`, `network_defense`, `endpoint_defense`, `identity_defense`, `cloud_security`, `iot_security`, `ot_security`, `malware_analyst`, `digital_forensics`, `compliance_officer`, `recovery_agent`.
- **RAG**: embeddings léxicos deterministas de 384 dimensiones (hash de tokens), almacenados en JSONB y similitud coseno en proceso (`services/rag/embeddings.py:1-60`). No es un modelo semántico.
- **Reglas SIEM builtin**: 6 plantillas (`modules/siem/builtin_rules.py:14-116`): fuerza bruta, port scan horizontal, match IOC, escalada de privilegios, hash malware, exfiltración.
- **Import Sigma**: subconjunto con conversión (`modules/siem/service.py:433-533`).
- **MCP**: cliente JSON-RPC real (`modules/mcp/client.py:35-105`), descubrimiento `tools/list`, ejecución `tools/call` con validación de esquema y aprobación.
- **Detección**: motor DSL + correlación + dedupe; se ejecuta en la transacción de ingesta (`services/detection.py:814-899`).
- **AI offline**: sin proveedor responde `503` y los agentes caen a modo determinista (declarado en `docs/implementation-status.md:83-86`).

---

## 11. FRONTEND

### 11.1 Rutas (`frontend/src/App.tsx:92-130`)

29 rutas (incluye login, index y wildcard). 28 ficheros de página, 26 pantallas de contenido + Login + NotFound.

| Ruta | Página |
| :--- | :--- |
| `/login` | Login (MFA inline) |
| `/` | ExecutiveOverview |
| `/soc` | Soc |
| `/monitoring` | Monitoring |
| `/incidents`, `/incidents/:incidentId` | Incidents, IncidentDetail |
| `/threat-intel` | ThreatIntel |
| `/siem` | Siem |
| `/assets`, `/assets/:assetId` | Assets, AssetDetail |
| `/attack-surface` | AttackSurface |
| `/vulnerabilities` | Vulnerabilities |
| `/soar` | Soar |
| `/playbook-designer`, `/playbook-designer/:playbookId` | PlaybookDesigner |
| `/agents` | Agents |
| `/iot-ot` | IotOt |
| `/network`, `/cloud`, `/identity` | Posture (network/cloud/identity) |
| `/forensics` | Forensics |
| `/compliance` | Compliance |
| `/integrations` | Connectors + MCP |
| `/models` | AI providers/models |
| `/audit` | Audit |
| `/organizations` | Organizations |
| `/admin` | Admin (edge, retention, kill switches) |
| `/profile` | Profile |
| `*` | NotFound |

### 11.2 Componentes y librerías

- `components/ui/index.tsx`: 32 exports (Button, Card, Kpi, DataTable, Modal, Pagination, Skeleton, EmptyState, ErrorBanner, Tabs, Toast, ScoreRing, AreaChart SVG, Sparkline, etc.). Sin dependencia de charts externa.
- `components/layout/`: AppShell, CommandPalette, navegación por 6 grupos y permisos (`navigation.ts:42-102`).
- `components/features/`: detect (grafo, tablas, tipos), govern (seguridad), protect (protocolos, descarga), respond (incidentes).
- `lib/`: `api.ts` (fetch tipado, CSRF, `X-Organization-Id`, errores), `auth.tsx`, `i18n.tsx` (ES/EN, 595 líneas), `query.ts`, `format.ts`.
- `styles/app.css`: 402 custom properties, `:root`, `[data-theme="light"]`, `prefers-reduced-motion` (`app.css:1,70,2269`).
- `index.html` sirve la SPA; Vite `outDir=dist`, `assetsDir=static` (`frontend/vite.config.ts:14-20`).

### 11.3 UI declarada y ausente

- No hay `EventSource`/SSE en `frontend/src` (0 coincidencias); las vistas “live” usan `refetchInterval` (`Monitoring.tsx:256,282`, `Soc.tsx:98`, `Incidents.tsx:499`).
- No hay virtualización de tablas, ni `axe-core`, ni páginas Mfa/Setup independientes.

---

## 12. TESTS

### 12.1 Backend — 519 tests recogidos

`pytest --collect-only -q -p no:cacheprovider` (sin BD, sin escribir caché): **519** tests en 37 ficheros.

| Suite | Tests | Ficheros representativos |
| :--- | ---: | :--- |
| `tests/integration` | 361 | agents 17, ai 28, assets 13, attack_surface 7, auth 17, compliance 16, connectors 22 + adapters 13 + security 16, defence 19, edge 17, events 15, forensics 12, incidents 18, ingest_security 11, iot_ot 8, mcp 17, organizations 7, posture 7, reports 15, siem 13, soar 28, threat_intel 17, vulnerabilities 8 |
| `tests/unit` | 121 | connector_normalize 30, detection 12, frameworks 10, normalization 22, prompt_safety 15, rag 12, risk 8, stix 12 |
| `tests/security` | 37 | audit_integrity 2, autonomy_guardrails 21, bootstrap 2, http_hardening 9, tenant_isolation 3 |

### 12.2 Edge — 92 tests

`edge/tests`: agent 12, client 15, cli 14, collectors 15, config 12, queue 13, signature 7. Recogidos: **92**.

### 12.3 Frontend — 36 unit + 13 E2E

- Vitest: 36 tests en 5 ficheros (`Assets.test.tsx` 10, `Compliance.test.tsx` 3, `Incidents.test.tsx` 4, `IotOt.test.tsx` 4, `Vulnerabilities.test.tsx` 15).
- Playwright: 13 tests (`all-screens.spec.ts` 5, `critical-flows.spec.ts` 7, `screenshots.spec.ts` 1).

### 12.4 Cobertura de dominios sin test dedicado

No hay tests específicos para: `posture` (solo 7), `reports` (15), `edge` core, `mcp` ejecución real (17 con dobles), `search`/FTS, `SSE` (inexistente), `rate_limit` a escala, `outbox` (inexistente), `workers` (claim/lease se cubre vía SOAR).

---

## 13. SCRIPTS, CI Y DESPLIEGUE

### 13.1 `scripts/` (9 ficheros, 462 líneas)

`setup.sh`, `verify_all.sh` (gate local), `backup.sh`, `restore.sh`, `sbom.sh`, `download_model.sh`, `smoke_api.py` (79 checks read-only), `bootstrap_admin.py`, `seed_demo.py`.

### 13.2 CI (`.github/workflows/ci.yml`, 5 jobs)

| Job | Contenido |
| :--- | :--- |
| `backend` | PostgreSQL 18 service, `pip install -e ./backend[dev]`, ruff check/format, mypy, pytest+cov, pip-audit, bandit |
| `frontend` | Node 22, `npm ci`, build, vitest, `npm audit` |
| `secret-scan` | gitleaks |
| `sbom` | CycloneDX Python + npm |
| `container` | build imagen + Trivy CRITICAL/HIGH |

No hay job de edge, E2E Playwright, K8s ni Compose.

### 13.3 Compose y Kubernetes

- Compose: `postgres` + `app` + `ollama` opcional. **No hay servicios worker/web** pese a `ARCHITECTURE.md:107` (“core, worker, web, postgres”).
- K8s: 1 Deployment (`replicas: 2`) que ejecuta uvicorn; **no hay Deployments/CronJobs para playbook_worker, connector_worker ni syslog**. Migración en Job separado.
- `HS_RUN_MIGRATIONS` por defecto `true` en la imagen (`Dockerfile:41-43`); en K8s se usa Job, en compose se ejecuta en el arranque.
- `infra/` está vacío: no hay tuning de PostgreSQL, proxy, systemd ni observabilidad.

---

## 14. SPECS, DOCS Y `.factory`

- `specs/`: 57 ficheros (12 ADR, 15 dominios, 6 arquitectura, contratos de API/integraciones, testing, operaciones, seguridad, producto).
- `docs/`: 29 ficheros; destacan `implementation-status.md`, `repository-audit.md`, `api-reference.md`, `compatibility-matrix.md`, `manual-uso-integracion.md`, `architecture-c4.md`, `openapi.json`.
- `.factory/`: `SPEC.md` 73 KB / 124 AC; `ARCHITECTURE.md` 55 KB; `TASKS.md` 108 KB; `SECURITY_AUDIT.md` 75 KB.

Estado declarado vs real en `.factory`:

| Métrica | Declarado | Real (snapshot) | Evidencia |
| :--- | :--- | :--- | :--- |
| Tareas verificadas | 138/176 (0.1.2) | 138 `[x]`, 37 `[!]`, 1 `[~]` | `scripts/factory_metrics.py` |
| Deferred | 37 + 1 en progreso | 37 `[!]`, 1 `[~]` | `.factory/TASKS.md` |
| AC verificados | 70/124 | 70 `VERIFIED`, 32 `PARTIAL`, 22 `NOT_VERIFIED` | `.factory/AC_TRACEABILITY.md` |
| Tests backend | 650 recogidos | 650 ejecutados (ver EVIDENCE) | `pytest --collect-only`, `.factory/EVIDENCE/` |
| Endpoints | 305 operaciones / 233 paths | 305 / 233 | `app.openapi()` vía `scripts/factory_metrics.py` |
| Seguridad | 0 CRITICAL / 0 HIGH abiertos | 0/0 con residuales aceptados | `.factory/SECURITY_AUDIT.md` |

---

## 15. DISCREPANCIAS DOCS/SPECS ↔ CÓDIGO (con evidencia)

| # | Documento afirma | Código real | Evidencia |
| :--- | :--- | :--- | :--- |
| D-01 | Transactional outbox + `LISTEN/NOTIFY` + tabla `jobs` | No existen tablas, modelos ni dispatcher | `.factory/ARCHITECTURE.md:22-23,69,138,362-381`; `grep -ri outbox backend/app` = 0 |
| D-02 | SSE `/events/stream` y `lib/sse.ts` | Sin endpoint ni cliente SSE; solo polling | `ARCHITECTURE.md:171,321,451`; `specs/domains/siem.md:88`; `grep EventSource` = 0 |
| D-03 | `repository.py` por dominio y regla M-03 | 0 ficheros `repository.py` | `ARCHITECTURE.md:80,124,137`; `find` = 0 |
| D-04 | Paginación por cursor `{data, meta.next_cursor}` | `{items, meta:{total,page,page_size,pages,has_next}}` con `OFFSET` | `specs/api/rest-contract.md:19`; `docs/api-reference.md:40`; `backend/app/core/schemas.py:39-80`; `modules/events/router.py:578-580` |
| D-05 | Error `{error:{code,message,fields}}` | `{error:{code,message,details,request_id}}` | `specs/api/rest-contract.md`; `backend/app/main.py:80-90` |
| D-06 | `POST /api/v1/setup` idempotente | No existe endpoint; bootstrap por script | `.factory/SPEC.md:156`; `specs/domains/organizations.md:56`; `scripts/bootstrap_admin.py` |
| D-07 | `GET /auth/password-policy` | No existe | `.factory/SPEC.md:148`; listado de endpoints auth |
| D-08 | `POST /assets/{id}/restore` + soft delete | Borrado físico (`db.delete`) y sin `deleted_at` | `specs/domains/assets.md:31,63`; `modules/assets/router.py:174-195` |
| D-09 | `GET /attack-surface/export?format=stix2.1|csv` | No existe; solo import STIX | `.factory/SPEC.md:196`; `specs/domains/attack-surface.md:62`; listado de endpoints |
| D-10 | `POST /vulnerabilities/import` multipart Nessus/OpenVAS/Trivy con 207 | Solo JSON CVE/KEV/EPSS; sin 207 en todo el backend | `.factory/SPEC.md:212`; `modules/vulnerabilities/router.py:92-149`; `grep status_code=207` = 0 |
| D-11 | `/events/webhook/{connector_id}` con `X-HS-Signature` | `/ingest/{source_token}` con HMAC opcional | `specs/domains/siem.md:27,85`; `modules/events/router.py:259-356` |
| D-12 | `/detection-rules` y versiones | `/siem/rules` con `version` entero | `specs/domains/siem.md:89-90`; `modules/siem/router.py:106-229` |
| D-13 | Cloud accounts/CSPM `/api/v1/cloud/*` | Sin módulo; `/posture/cloud` derivado | `specs/domains/cloud.md:6,57-60`; `modules/posture/router.py:20-23` |
| D-14 | Invitaciones y aceptación por token | Sin tabla ni endpoints | `specs/domains/organizations.md:66`; `grep invitations` = 0 |
| D-15 | Recovery codes MFA (10) | No implementados | `specs/domains/identity.md:26`; `docs/compatibility-matrix.md:109`; `grep recovery_code` = 0 |
| D-16 | `Idempotency-Key` en ingesta/ejecución/import | No se lee en ningún endpoint | `docs/api-reference.md:43`; `grep Idempotency-Key` = 0 |
| D-17 | `X-Organization-Id` obligatorio (400 si falta) | Opcional; usa la org de sesión/token | `.factory/SPEC.md:160`; `backend/app/core/deps.py:195,240-245` |
| D-18 | UUIDv7 en PK | `uuid.uuid4()` | `ARCHITECTURE.md:193,211`; `core/db.py:37` |
| D-19 | Soft delete en dominio | Solo `organizations.deleted_at` | `ARCHITECTURE.md:202`; `models/core.py:39` |
| D-20 | FTS `tsvector` para búsqueda | Índice GIN creado, pero queries con `LIKE '%q%'` | `0002_hardening.py:37-53`; `modules/events/router.py:566-576`; `modules/assets/router.py:76-85`; `modules/overview/router.py:322-404` |
| D-21 | Eventos particionados por mes | Tabla única | `specs/domains/siem.md`; migración inicial `security_events` |
| D-22 | `uplot` y `axe-core` | No están en `package.json`; charts SVG propios | `ARCHITECTURE.md:32-33`; `frontend/package.json`; `components/ui/index.tsx:761` |
| D-23 | OpenAPI en `/api/v1/openapi.json`, Swagger `/api/v1/docs` | `/api/openapi.json`, `/api/docs` | `docs/api-reference.md:6`; `backend/app/main.py:107-109` |
| D-24 | Snapshot OpenAPI 283 ops / 214 paths | 284 ops / 215 paths | `docs/openapi.json`; AST |
| D-25 | 23/24 pantallas | 26 pantallas de contenido + Login + NotFound (28 ficheros) | `README.md:90,208`; `implementation-status.md:53`; `frontend/src/App.tsx:93-128` |
| D-26 | Pins FastAPI `^0.115`, cryptography `^44`, numpy `^2.1`, pytest `^8` | `0.165.0`, `50.0.0`, `2.2.6`, `9.0.3` | `ARCHITECTURE.md:17-25`; `backend/pyproject.toml:7-38` |
| D-27 | 12 dominios (roadmap) | 23 módulos montados | `docs/roadmap.md:13`; `app/api/router.py` + `ls modules/*/router.py` = 23 |
| D-28 | Compose con core, worker, web, postgres | postgres, app, ollama | `ARCHITECTURE.md:107`; `deploy/compose/docker-compose.yml` |
| D-29 | Procesos `hispanshield-worker-*` | Solo scripts manuales/cron; sin despliegue | `ARCHITECTURE.md:183`; `deploy/k8s/manifests.yaml`; `Dockerfile:43` |
| D-30 | `tests/autonomy/` y `test_prompt_injection.py` | No existen; la cobertura está en `test_autonomy_guardrails.py` y `test_prompt_safety.py` | `specs/testing/strategy.md:96-97`; `ls backend/tests` |
| D-31 | 515 tests / 109 tareas | 519 tests / 106 `[x]` + 44 `[!]` | `implementation-status.md:12,23`; conteo real |
| D-32 | `ARCHITECTURE.md` mapea rutas `/overview`, `/threats/live`, `/ai/agents`, `/playbooks/designer`, `/ai/models` | Rutas reales `/`, `/soc`, `/monitoring`, `/agents`, `/playbook-designer`, `/models` | `ARCHITECTURE.md:447-467`; `frontend/src/App.tsx:101-127` |
| D-33 | `readyz` devuelve `db`, `migrations`, `queue_depth` | Implementado + `outbox` backlog | `backend/app/main.py`; `test_auth.py::test_health_endpoints` |

### Reconciliation 0.1.2 (2026-11-26)

Este inventario conserva el snapshot del baseline para trazabilidad. Cambios
cerrados en la ola 0.1.2:

- **D-01:** outbox transaccional con leases/retries/DLQ implementado; faltan
  `LISTEN/NOTIFY` y tabla `jobs` separada (`TASK-008` en progreso).
- **D-02:** SSE `/events/stream` + cliente `useEventStream` implementados.
- **D-04:** cursor pagination aditiva (`meta.next_cursor`) en assets/events;
  offset sigue soportado.
- **D-06/D-07/D-14/D-15:** `/setup`, `/auth/password-policy`, invitaciones y
  recovery codes implementados y testeados.
- **D-16:** `Idempotency-Key` implementado en incidentes, import de activos y
  CVE.
- **D-24:** OpenAPI actual: 305 operaciones / 233 paths.
- **D-25:** 23 pantallas de navegación, 26 componentes de contenido, 28 ficheros
  incluyendo Login/NotFound.
- **D-31:** 650 tests recogidos; 138/176 tareas verificadas.

Siguen abiertos: D-03 (repository layer), D-08 (soft delete), D-09/D-10
(export/importers), D-13 (cloud/CSPM), D-17 (header obligatorio), D-18
(UUIDv7), D-19, D-20 (FTS real), D-21 (particiones), D-23 (ruta OpenAPI),
D-26 (pins), D-29 (runtime K8s no ejecutado).
| D-34 | Matriz de compatibilidad: Nessus/OpenVAS/Trivy y recovery codes “supported” | Ausentes | `docs/compatibility-matrix.md:109,122-124` |

---

## 16. FUNCIONALIDAD DOCUMENTADA PERO AUSENTE O SIMPLIFICADA

Lista consolidada (sin pretender exhaustividad):

**Identidad/tenancy**
- Invitaciones con token y TTL 72 h (`specs/domains/organizations.md:66`).
- Recovery codes MFA (`specs/domains/identity.md:26`).
- Listado/revocación de sesiones activas del usuario (no hay endpoint).
- Borrado de organización con confirmación por nombre y purga a 30 días (AC-14).
- Historial de contraseñas (5 hashes), denylist de 10k contraseñas (solo 9 en `core/schemas.py:16-26`).
- `/setup` transaccional.

**Inventario/exposición**
- Soft delete + restore de activos; import CSV/JSON con 207 y transacción por fila (el import es JSON y devuelve 200).
- `exposure_diffs`, observaciones autorizadas, export STIX/CSV de superficie.
- Inventario cloud y CSPM real (AWS/Azure/GCP), CPE/firmware/EOL, checklist ETSI de 13 provisiones, `required_sl` obligatorio.

**Vulnerabilidades**
- Importadores Nessus/OpenVAS/Trivy; excepciones de riesgo con caducidad; máquina de estados con evidencia obligatoria.

**SIEM**
- Particiones mensuales, SSE, `Idempotency-Key`, webhook `X-HS-Signature` por conector, versionado de reglas con tabla de versiones.
- Correlación a incidentes entendida como motor multi-evento (existe dedupe/promote, no un motor de correlación avanzado).

**SOAR/autonomía**
- Versionado de playbooks (solo `version` entero), nodos de aprobación con timeout/doble aprobación, límites de concurrencia por org, budgets por hora, ventanas de cambio congelado, A4 con doble aprobación, laboratorio de autonomía.
- Dos acciones (`patch.apply`, `configuration.restore`) sin adaptador.

**IA**
- Runtime durable de agentes con step log/reanudación, presupuesto de coste por organización. RAG semántico real (hoy embeddings léxicos hash).

**CTI/forense/cumplimiento**
- Campañas, relaciones CTI, TTL/decaimiento, export STIX; legal hold, manifiesto de caso, export ZIP forense; RoPA/DPIA, tracker NIS2 24/72 h/1 mes, informes PDF, firma/hash verificable expuesta.

**Plataforma**
- Settings, feature flags, SSE, bundle air-gapped, HA, particiones, outbox/jobs.

---

## 17. DATOS DEMO Y COMPORTAMIENTO “MOCK”

- `backend/app/seed.py` (1.682 líneas) y `scripts/seed_demo.py` generan una organización demo (`Ayuntamiento de Nova Iberia (demo)`) con activos, eventos, incidentes y evidencias. Es demo explícita, no producción.
- `backend/data/evidence/...` y `data/evidence/...` contienen 3 ficheros de evidencia demo (≈1,5 MB).
- `services/rag/embeddings.py` es un baseline léxico determinista, no semántico (documentado honestamente en el propio módulo).
- La ausencia de LLM se trata como estado `unavailable` (503) y los agentes usan fallback determinista, según `docs/implementation-status.md:83-86`.
- No se encontraron `TODO`/`FIXME`/`placeholder` en `backend/app` salvo dos cadenas legítimas: sustitución de `${...}` en playbooks (`modules/soar/validation.py:501`) y “Rollback is not implemented for this connector capability” (`services/connectors/base.py:84`).

---

## 18. RESUMEN EJECUTIVO DEL INVENTARIO

- Producto **monolito modular FastAPI + PostgreSQL + SPA React**, 23 dominios cableados, 284 endpoints, 59 tablas, 7 migraciones, 12 adaptadores de conector, 16 agentes, 10 frameworks/105 controles.
- Calidad de implementación alta en: tenancy/RBAC, auditoría encadenada, SOAR durable, broker de autonomía, MCP, edge store-and-forward, OCSF, compliance determinista.
- La deuda principal no es “código vacío”, sino **drift entre contrato declarado e implementación**: outbox/jobs/SSE, paginación cursor, cloud/CSPM, importadores de escáneres, recovery codes, workers desplegables, catálogo de conectores y varias promesas de docs.
- El árbol está **en remediación activa** (0007, bootstrap, logging, forensics), por lo que los conteos pueden variar en el siguiente commit.
