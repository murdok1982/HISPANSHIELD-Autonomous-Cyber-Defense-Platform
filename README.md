# HISPANSHIELD

**Plataforma de ciberdefensa autónoma para administraciones públicas y operadores de infraestructuras críticas.**

HISPANSHIELD unifica inventario, superficie de exposición, vulnerabilidades, SIEM, SOAR, threat intelligence, gestión de incidentes, forense digital y cumplimiento normativo europeo (NIS2, CRA, GDPR, ENS, ISO/IEC 27001/27002, IEC 62443, ETSI EN 303 645) sobre un despliegue **on-premise o air-gapped**, con **respuesta autónoma gobernada por política** y **IA local opcional**.

> **Estado del repositorio:** fase de **especificación (SDD)**. Los contratos, criterios de aceptación y backlog están congelados; la implementación se ejecuta contra `.factory/TASKS.md`. Ninguna funcionalidad está marcada como `VERIFIED` todavía. Ver `docs/implementation-status.md`.

---

## 1. PRINCIPIOS

- **Soberanía del dato:** nada sale del perímetro sin opt-in explícito y auditado.
- **Deny-by-default:** autorización, política de autonomía y tool-calls deniegan salvo permiso explícito.
- **Trazabilidad:** cadena de auditoría con hash encadenado; evidencias con SHA-256.
- **Reversibilidad:** toda acción autónoma declara verificación y rollback.
- **Honestidad:** si un conector, sensor o modelo no está disponible, se muestra `unavailable`/`degraded` con causa. Nunca datos fabricados.
- **Accesibilidad:** WCAG 2.2 AA en las 23 pantallas operativas.

---

## 2. STACK

| Capa | Tecnología |
| :--- | :--- |
| Backend | Python 3.12 · FastAPI · SQLAlchemy 2.0 (sync) · psycopg3 · Alembic · Pydantic v2 |
| Base de datos | PostgreSQL 18 (JSONB, FTS, particiones, `SKIP LOCKED`, `LISTEN/NOTIFY`) |
| Frontend | React 19 · TypeScript strict · Vite · CSS Modules + design tokens propios |
| Edge | Python 3.12 · SQLite WAL · mTLS |
| IA | Ollama / vLLM (local) · proveedor externo opt-in |
| Calidad | pytest · Vitest · Playwright · axe-core · ruff · mypy · bandit · pip-audit · gitleaks |

Sin Kafka, Redis, OpenSearch, Qdrant, Temporal, Keycloak ni Vault. Ver `specs/adr/`.

---

## 3. ESTRUCTURA

```text
.
├── backend/            # API + workers + migraciones + tests
├── frontend/           # SPA React (23 pantallas) + E2E
├── edge/               # gateway store-and-forward
├── deploy/             # compose + kubernetes
├── infra/              # proxy, systemd, observabilidad
├── scripts/            # verify_all, backup, restore, sbom, airgap
├── specs/              # SDD: constitución, producto, arquitectura, 15 dominios, ADRs
├── docs/               # auditoría, plan, C4, manuales, referencia API
├── .factory/           # SPEC, ARCHITECTURE, TASKS, SECURITY_AUDIT
├── reports/            # SBOM, rendimiento, auditorías (generados)
└── examples/           # payloads de ejemplo (OCSF, STIX, CSV, prompts)
```

---

## 4. PUESTA EN MARCHA (DESARROLLO)

### 4.1 Requisitos verificados

| Herramienta | Versión |
| :--- | :--- |
| Python | 3.12.16 (`/tmp/opencode/hs-venv`) |
| PostgreSQL | 18.6 en `/tmp/opencode:55432` (trust auth) |
| Node.js | 22.14.0 |
| npm | 10.9.2 |

```bash
export PATH=/tmp/opencode/node-v22.14.0-linux-x64/bin:$PATH
source /tmp/opencode/hs-venv/bin/activate
export HISPANSHIELD_DATABASE_URL="postgresql+psycopg://postgres@/hispanshield?host=/tmp/opencode&port=55432"
```

### 4.2 Backend

```bash
cd backend
uv sync
alembic upgrade head
uvicorn app.main:app --reload --port 8000
```

### 4.3 Frontend

```bash
cd frontend
npm ci
npm run dev        # http://localhost:5173 (proxy a :8000)
```

### 4.4 Primer acceso

1. Abrir `http://localhost:5173/setup` (solo si no existe ninguna organización).
2. Crear organización + usuario `owner`.
3. Configurar MFA en el primer login.
4. (Opcional) Registrar un proveedor IA local en `/ai/models`.

---

## 5. VARIABLES DE ENTORNO

| Variable | Obligatoria | Default | Descripción |
| :--- | :---: | :--- | :--- |
| `HISPANSHIELD_ENV` | ✅ | `production` | `production|staging|test` |
| `HISPANSHIELD_DATABASE_URL` | ✅ | — | `postgresql+psycopg://...` |
| `HISPANSHIELD_SECRET_KEY` | ✅ (prod) | — | Clave Fernet (32 bytes base64) |
| `HISPANSHIELD_ALLOWED_ORIGINS` | ✅ | — | Orígenes CORS exactos, separados por coma |
| `HISPANSHIELD_EVIDENCE_PATH` | ✅ | — | Volumen de evidencias |
| `HISPANSHIELD_SESSION_IDLE_MINUTES` | — | `30` | Timeout de inactividad |
| `HISPANSHIELD_SESSION_ABSOLUTE_HOURS` | — | `12` | Timeout absoluto |
| `HISPANSHIELD_REQUIRE_MIGRATIONS` | — | `true` | Bloquea arranque si hay migraciones pendientes |
| `HISPANSHIELD_EDGE_REQUIRE_MTLS` | — | `false` | Exige certificado de cliente |
| `HISPANSHIELD_AI_PROVIDER` | — | `none` | `none|ollama|vllm|openai_compat` |
| `HISPANSHIELD_AI_BASE_URL` | — | — | Endpoint local |
| `HISPANSHIELD_AI_DAILY_TOKEN_BUDGET` | — | `0` | 0 = sin límite (no recomendado) |

Generar la clave:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

`.env` nunca se versiona. Ver `.env.example`.

---

## 6. VERIFICACIÓN

```bash
# Todo
bash scripts/verify_all.sh

# Por área
cd backend && ruff check . && mypy --strict app && pytest -q
cd frontend && npm run typecheck && npm run build && npm run test
cd frontend && npm run test:e2e
cd backend && pytest -q tests/security/test_tenant_isolation.py
cd backend && pytest -q tests/autonomy/
pip-audit -r backend/requirements.txt && bandit -r backend edge -ll
gitleaks detect --no-banner --redact
bash scripts/generate_sbom.sh && python scripts/check_licenses.py
bash scripts/backup_restore_drill.sh
bash scripts/verify_airgap.sh
```

Cada `AC-XX` de `.factory/SPEC.md §3` tiene un test mapeado en `specs/testing/matrix.md`.

---

## 7. DOCUMENTACIÓN

| Necesitas | Documento |
| :--- | :--- |
| Qué es y por qué | `specs/product/vision.md` |
| Qué entra y qué no | `specs/product/scope.md` |
| Requisitos y ACs | `.factory/SPEC.md`, `specs/product/requirements.md` |
| Arquitectura | `.factory/ARCHITECTURE.md`, `docs/architecture-c4.md` |
| Decisiones (ADR) | `specs/adr/` |
| Dominios funcionales | `specs/domains/` |
| Seguridad y autonomía | `specs/security/` |
| API | `specs/api/rest-contract.md`, `docs/api-reference.md` |
| Operación | `docs/operations-runbook.md`, `specs/operations/` |
| SOC | `docs/soc-manual.md` |
| Incidentes | `docs/incident-response-manual.md` |
| IoT/OT | `docs/iot-ot-manual.md` |
| Recuperación | `docs/recovery-manual.md` |
| Auditoría | `docs/audit-manual.md` |
| Conectores | `docs/connector-guide.md` |
| IA local | `docs/local-models-guide.md` |
| Agentes | `docs/agents-guide.md` |
| Estado real | `docs/implementation-status.md` |

---

## 8. SEGURIDAD

- No se aceptan secretos en el repositorio: `gitleaks` bloquea el gate.
- Vulnerabilidades del producto: ver `SECURITY.md` (divulgación responsable y plazos).
- La clave `HISPANSHIELD_SECRET_KEY` la custodia el operador; sin ella, los secretos cifrados son irrecuperables.
- Despliegue en producción: TLS + HSTS, PostgreSQL con autenticación fuerte (no trust), backups cifrados y probados.

---

## 9. LICENCIA Y ORIGINALIDAD

Construcción **clean-room**: no deriva de `SmartNationDefense` ni de ningún producto con licencia incompatible. Ver `docs/repository-audit.md`, `docs/license-policy.md` y `specs/adr/ADR-012-license-clean-room.md`. La licencia de distribución del producto se define en el contrato de despliegue; las dependencias cumplen la allowlist documentada.

---

## 10. ESTADO

| Elemento | Estado |
| :--- | :--- |
| Especificación (SDD) | ✅ Congelada v1.0 |
| Backlog | ✅ 150 tareas en 12 fases |
| Implementación | ⏳ Pendiente (`0 / 150`) |
| Auditoría de seguridad | ⏳ Pendiente (`SECURITY_AUDIT.md` en `BLOCKED`) |
| Release 1.0 | ⏳ No iniciada |

El Exit Gate exige: 150/150 tareas, 124/124 ACs con test verde, `0 CRITICAL/HIGH`, air-gap y backup verificados.
