# ARCHITECTURE GAP ANALYSIS — HISPANSHIELD

> **Snapshot histórico (baseline RC1).** Se conserva para trazabilidad. El estado
> reconciliado y las capacidades cerradas en 0.1.2 están en
> `.factory/REPO_INVENTORY.md` §“Reconciliation 0.1.2”, `.factory/AC_TRACEABILITY.md`
> y `.factory/EVIDENCE/`.


- **Fecha:** 2026-11-26
- **Base:** `.factory/ARCHITECTURE.md`, `.factory/SPEC.md`, `specs/**`, `docs/**` confrontados con el código en el árbol de trabajo (`HEAD 696655b` + snapshot inicial de 14 modificados/2 untracked; el diff creció a 24 archivos durante la sesión). Los conteos pueden variar en el siguiente commit.
- **Alcance:** diferencias de arquitectura, acoplamientos, deuda estructural, riesgos de escalabilidad, módulos declarados no cableados y priorización P0/P1/P2.
- **Regla:** toda afirmación se apoya en ruta:línea. Los conteos están en `.factory/REPO_INVENTORY.md`.

---

## 1. RESUMEN EJECUTIVO

La implementación es un **monolito modular FastAPI coherente y funcional en su núcleo** (identidad/tenancy, activos, vulnerabilidades, SIEM, incidentes, SOAR durable, autonomía gobernada, conectores, IoT/OT, edge, cumplimiento, informes). No es un esqueleto: hay 284 endpoints, 59 tablas, 12 adaptadores y 519 tests backend + 92 edge + 36 frontend.

El gap principal es **de contrato, no de volumen de código**:

1. La arquitectura declarada describe una plataforma con **outbox transaccional, tabla `jobs`, SSE, capa `repository.py`, particiones, cursor pagination y UUIDv7**. Nada de eso existe (ver §3–§5).
2. El **catálogo de integraciones y la matriz de compatibilidad prometen** cloud CSPM, Splunk/QRadar, EDR de terceros, ticketing, SMTP, importadores Nessus/OpenVAS/Trivy y recovery codes. El código solo tiene 12 adaptadores y 4 tipos de proveedor IA.
3. El **despliegue no arranca los workers** que hacen durable SOAR y sync de conectores: `playbook_worker`, `connector_worker` y `run_syslog` son scripts manuales; compose/k8s solo ejecutan la API.
4. La **trazabilidad SDD está rota**: 124 AC en `SPEC.md`, 0 marcados `[x]`; `TASKS.md` 106 `[x]`/44 `[!]`; `implementation-status.md` afirma 109/47.
5. Hay **dos acciones del catálogo sin adaptador** (`patch.apply`, `configuration.restore`) y **una acción A4 inexistente**: el producto declara A0–A4 pero el nivel A4 no tiene ninguna acción.

Riesgo de escala dominante: **PostgreSQL único con SQLAlchemy sync**, rate limiting con lock de fila por petición, búsqueda `LIKE '%q%'` sin usar el índice FTS, detección síncrona en la transacción de ingesta y RAG O(n) en Python sobre JSONB.

---

## 2. MÉTODO Y FUENTES

| Fuente | Uso |
| :--- | :--- |
| `.factory/ARCHITECTURE.md` | topología, stack, reglas M-01…M-07, contratos, ADR |
| `.factory/SPEC.md` | 124 AC, scope in/out |
| `specs/adr/*`, `specs/domains/*`, `specs/api/rest-contract.md`, `specs/integrations/*` | contratos normativos |
| `docs/implementation-status.md`, `docs/compatibility-matrix.md`, `docs/api-reference.md`, `README.md` | promesas de producto |
| `backend/app/**`, `backend/migrations/**`, `frontend/src/**`, `deploy/**`, `edge/**` | realidad ejecutable |
| AST + `pytest --collect-only` | conteos verificables |

Los “gaps” se clasifican en:
- **G-A Contrato:** el doc y el código no coinciden (aunque el código sea razonable).
- **G-B Implementación ausente:** la capacidad declarada no existe.
- **G-C Estructura:** la implementación existe pero viola las fronteras/decisiones arquitectónicas.
- **G-D Operación:** existe en código pero no es desplegable/operable como se declara.

---

## 3. GAPS DE CONTRATO (G-A)

### 3.1 API: paginación, errores e idempotencia

| Contrato declarado | Implementación | Impacto |
| :--- | :--- | :--- |
| Cursor `{data[], meta:{next_cursor,total_estimate}}` (`specs/api/rest-contract.md:19`; `docs/api-reference.md:40`) | `Page{items[], meta:{total,page,page_size,pages,has_next}}` con `OFFSET` (`backend/app/core/schemas.py:39-80`; `modules/events/router.py:578-580`) | Contratos de cliente incompatibles; `OFFSET` profundo degrada a escala |
| Error `{error:{code,message,fields?}}` | `{error:{code,message,details,request_id}}` (`backend/app/main.py:80-90`) | Clientes que esperan `fields` fallan; tests/documentos divergen |
| `Idempotency-Key` en ingesta/ejecución/import (`docs/api-reference.md:43`) | No se lee en ningún endpoint (`grep` = 0) | Reintentos de cliente pueden duplicar ejecuciones/imports; solo la ingesta tiene `dedupe_key` |
| `X-Organization-Id` obligatorio → `400 organization_header_required` (`.factory/SPEC.md:160`) | Opcional; se usa la org de sesión/token (`core/deps.py:195,240-245`) | Cambia el modelo de selección de tenant y los tests de contrato |
| OpenAPI en `/api/v1/openapi.json` (`docs/api-reference.md:6`) | `/api/openapi.json` (`main.py:107-109`) | Documentación y automatizaciones apuntan a una URL inexistente |

**Decisión requerida (P0):** o se implementa cursor/`fields`/`Idempotency-Key`, o se corrigen specs, docs, SDK y tests para declarar page/`details` como contrato. Mantener ambos es deuda permanente.

### 3.2 Rutas declaradas que no existen

| Ruta declarada | Evidencia | Estado real |
| :--- | :--- | :--- |
| `POST /api/v1/setup` | `.factory/SPEC.md:156`; `specs/domains/organizations.md:56` | Solo `scripts/bootstrap_admin.py` |
| `GET /auth/password-policy` | `.factory/SPEC.md:148` | Ausente |
| `POST /assets/{id}/restore` | `specs/domains/assets.md:31,63` | Ausente; borrado físico (`modules/assets/router.py:174-195`) |
| `GET /attack-surface/export` | `.factory/SPEC.md:196`; `specs/domains/attack-surface.md:62` | Ausente |
| `POST /vulnerabilities/import` (Nessus/OpenVAS/Trivy, 207) | `.factory/SPEC.md:212` | Solo `import/cve|kev|epss` (JSON) |
| `POST /events/webhook/{connector_id}` | `specs/domains/siem.md:27,85` | Equivalente distinto: `/ingest/{source_token}` |
| `GET/POST /detection-rules` y `/versions` | `specs/domains/siem.md:89-90` | Movido a `/siem/rules`; versión entera sin histórico |
| `GET /events/stream` (SSE) | `specs/domains/siem.md:88`; `ARCHITECTURE.md:321` | Ausente |
| `/cloud/accounts*` | `specs/domains/cloud.md:57-60` | Ausente; `/posture/cloud` derivado |
| `/invitations/{token}/accept` | `specs/domains/organizations.md:66` | Ausente |

Esto no es solo documental: los **AC-09, AC-13, AC-18, AC-25, AC-31** dependen de estas rutas y hoy no pueden verificarse.

### 3.3 Arquitectura declarada vs materialización

`.factory/ARCHITECTURE.md:118-128` mapea capas conceptuales. Contraste real:

| Capa declarada | Ruta declarada | Realidad |
| :--- | :--- | :--- |
| `repositories/<dominio>.py` | `app/modules/<d>/repository.py` | **0 ficheros**; SQL inline en routers/services |
| `detection/*` | `app/modules/siem/{engine,dsl}.py` | `app/services/detection.py` (fuera de módulo) |
| `workflow/*` | `app/modules/soar/{engine,steps}.py` | `app/services/playbook_engine.py` |
| `autonomy/*` | `app/modules/defence/{policy,broker,...}.py` | `app/services/{policy_engine,broker,actions}.py` |
| `services/public.py` | contrato interno | No existe (`ARCHITECTURE.md:532`) |
| Jobs/outbox | `models/events.py` + tablas | No existen (`ARCHITECTURE.md:22-23,69,377-381`) |

El código es funcional, pero la topología documentada **no describe el código**. Cualquier onboarding o auditoría basada en `ARCHITECTURE.md` obtiene un mapa incorrecto.

---

## 4. GAPS DE IMPLEMENTACIÓN AUSENTE (G-B)

### 4.1 Cloud / CSPM (P0 por promesa comercial)

- `specs/domains/cloud.md` marca el dominio como `SPECIFIED`; `docs/compatibility-matrix.md:83-85` y `specs/integrations/compatibility-matrix.md:99-104` declaran AWS/Azure/GCP **supported**.
- No hay `backend/app/services/{cloud,cspm}.py`, ni `modules/cloud/`, ni tablas `cloud_accounts`/`cloud_resources`, ni adaptadores.
- La pantalla `/cloud` (`frontend/src/pages/Cloud.tsx:243`) consume `GET /posture/cloud`, que agrega activos `kind=cloud` y hallazgos; **no hay descubrimiento, credenciales, reglas CSPM ni logs de auditoría cloud**.
- `docs/manual-uso-integracion.md:483` reconoce que la postura se deriva de inventario, contradiciendo la matriz.

**Riesgo:** un evaluador que pruebe “onboarding de cuenta AWS” concluye que la capacidad no existe. Debe marcarse `unsupported/roadmap` en todas las matrices o implementarse (P1 si no hay compromiso comercial inmediato; P0 de honestidad documental).

### 4.2 Conectores declarados vs 12 reales

Declarados en README/matrices pero sin adaptador:
- EDR: CrowdStrike, SentinelOne, Elastic Defend (`README.md:272`).
- Red: Palo Alto, Fortinet, Cisco (`README.md:273`).
- SIEM: IBM QRadar, Splunk, Google SecOps (`README.md:270`; `docs/compatibility-matrix.md:61`).
- SOAR: Shuffle, Cortex XSOAR, Splunk SOAR, Tines (`README.md:271`).
- Protocolos: `cloud_audit_pull`, `splunk_hec`, `ticketing_api`, `email_smtp` (`specs/integrations/protocol-registry.md:44,48,65,66`).

Además, dos acciones del catálogo no tienen capacidad instalada:
- `configuration.restore` → `restore_configuration` (`services/actions.py:145`) → ningún adaptador.
- `patch.apply` → `apply_patch` (`services/actions.py:156`) → ningún adaptador.

El broker lanzará `ServiceUnavailable` (`services/connectors/runtime.py:107-118`); la UI puede ofrecer acciones que nunca se ejecutarán. **P0:** filtrar el catálogo por capacidades realmente instaladas o implementar adaptadores.

### 4.3 Identidad: recovery codes y sesiones

- `specs/domains/identity.md:26` exige 10 recovery codes; `docs/compatibility-matrix.md:109` los declara soportados. No existen en modelo ni endpoints (`grep recovery_code` = 0).
- No hay endpoint para listar/revocar sesiones activas del usuario (solo `GET /auth/api-tokens`).
- No hay historial de contraseñas ni denylist de 10k (solo 9 entradas en `core/schemas.py:16-26`).
- `session_idle_minutes` por defecto 60 (`core/config.py:29`), mientras AC-06 declara 30 (`.factory/SPEC.md:146`).
- No hay borrado de organización (AC-14) aunque `organizations.deleted_at` existe (`models/core.py:39`).

### 4.4 SIEM a escala

- `security_events` es una tabla única; no hay particiones mensuales (SPEC “almacenamiento particionado”).
- El índice GIN FTS se crea (`migrations/versions/0002_hardening.py:37-53`) pero **no se usa**: las búsquedas son `LIKE '%q%'` (`modules/events/router.py:566-576`; `assets/router.py:76-85`; `overview/router.py:322-404`). El índice es coste de escritura sin beneficio de lectura.
- No hay SSE ni WebSocket; las vistas “live” hacen polling (`Monitoring.tsx:256,282`).
- No hay `Idempotency-Key` ni nonce anti-replay específico (el audit marca VULN-010 OPEN).

### 4.5 SOAR/autonomía avanzada

- Sin tabla de versiones de playbook (solo `version` entero, `models/incidents.py:102`); sin nodos de aprobación con timeout/doble aprobación; sin límite de concurrencia por organización.
- Sin presupuesto de acciones/hora, ventanas de cambio congelado ni blast radius (`grep budget|freeze|blast` en `policy_engine/broker/actions` = 0). El propio `SECURITY_AUDIT.md` lo registra como VULN-013 OPEN.
- Nivel A4 existe en `LEVELS` (`services/actions.py:185`) pero **ninguna acción lo usa** (0 `min_level="A4"`).
- Sin runtime durable de agentes con reanudación (TASK-093 `[!]`).

### 4.6 Forense/cumplimiento

- Sin legal hold, manifiesto de caso, export ZIP; `evidence` no tiene `legal_hold` (`grep` = 0).
- Sin RoPA/DPIA ni tracker NIS2 24/72 h/1 mes (`grep` = 0).
- Informes solo HTML/Markdown con `checksum` (`models/compliance.py:108-113`); no PDF ni firma verificable expuesta (TASK-117 `[!]`).

---

## 5. GAPS ESTRUCTURALES (G-C)

### 5.1 Violaciones de las reglas M-01…M-07

| Regla | Declaración | Evidencia de incumplimiento |
| :--- | :--- | :--- |
| M-01 (router sin lógica) | `ARCHITECTURE.md:135` | `overview/router.py` 455 líneas con SQL de negocio (`:230-455`); `organizations/router.py` 501; `soar/router.py` 570 |
| M-02 (sin imports service-service) | `ARCHITECTURE.md:136` | `iot/router.py:18` → `assets.service`; `ot/router.py:20`; `attack_surface/service.py:17`; `organizations/router.py:19` → `auth.service`; `services/playbook_engine.py:43-50` → 3 módulos (dirección inversa) |
| M-03 (repository obligatorio) | `ARCHITECTURE.md:137` | 0 `repository.py`; SQL directo en routers y services |
| M-04 (outbox en toda escritura) | `ARCHITECTURE.md:138` | No hay outbox |
| M-05 (workers solo casos de uso públicos) | `ARCHITECTURE.md:139` | `playbook_engine` importa services internos; no hay `services/public.py` |
| M-06 (no serializar ORM) | `ARCHITECTURE.md:140` | Mayoría usa `response_model`/schemas; `overview` devuelve `dict[str,Any]` construidos a mano (`overview/router.py:319-404`) |
| M-07 (edge sin código backend) | `ARCHITECTURE.md:141` | Cumple: `edge/` solo importa stdlib + httpx |

No existen los tests que la arquitectura cita como verificación: `test_architecture.py`, `test_import_boundaries.py`, `test_outbox_atomicity.py`, `test_no_orm_leak.py`, `edge/tests/test_contract.py` (0 coincidencias en `backend/tests`).

### 5.2 “Shared kernel” de facto sin contrato

`assets` actúa como módulo base: `iot`, `ot`, `vulnerabilities` y `attack_surface` importan `assets.schemas`/`assets.service`. No hay interfaz publicada ni versión; cualquier cambio en `AssetRef`/`ensure_zone_exists` rompe cuatro dominios. Es el acoplamiento más fuerte del sistema.

### 5.3 Dependencia invertida services → modules

`services/playbook_engine.py` importa `modules.defence.service`, `modules.incidents.service` y `modules.soar.validation` (`:43-50`). La capa supuestamente genérica depende de tres dominios, lo que:
- impide extraer el motor a un paquete/worker independiente sin arrastrar los módulos;
- crea riesgo de import circular al mover lógica a services;
- contradice el flujo `router → service → models`.

### 5.4 Autodescubrimiento con fallo total

`app/api/router.py:32-37` solo ignora `ModuleNotFoundError` cuando falta exactamente `<m>.router`; cualquier otro `ImportError` en un módulo aborta el arranque de toda la API. Un error de import en un dominio tumba los 23. No hay aislamiento por módulo ni health por dominio.

### 5.5 Módulos declarados y no cableados (o cableados parcialmente)

| Módulo | API | UI | Worker/Deploy | Observación |
| :--- | :--- | :--- | :--- | :--- |
| `cloud` (spec) | ❌ | Vista derivada | ❌ | Dominio declarado inexistente |
| `reports` | ✅ 5 | Indirecta (Compliance) | n/a | Sin pantalla propia |
| `edge` | ✅ 12 | Solo Admin | ❌ | Sin proceso edge en deploy |
| `mcp` | ✅ 13 | Dentro de Integrations | n/a | Sin entrada de navegación propia |
| `defence` | ✅ 11 | Soar/Admin | n/a | Sin página de remediaciones |
| `posture` | ✅ 4 | Network/Cloud/Identity | n/a | Sustituye a dominios reales de cloud/identity |
| `soar` | ✅ 15 | Soar + Designer | ⚠️ script | Ejecución durable depende de cron externo |
| `connectors` | ✅ 12 | Integrations | ⚠️ script | Sync depende de cron externo |
| `events` (syslog) | ✅ 16 | Monitoring | ⚠️ script | Listener opt-in, no desplegado |

No hay ningún módulo completamente huérfano a nivel API; el problema es **operativo** (workers) y **de profundidad** (cloud/identity reales sustituidos por vistas de postura).

---

## 6. GAPS DE OPERACIÓN Y DESPLIEGUE (G-D)

### 6.1 Workers no desplegados

`ARCHITECTURE.md:183` declara `hispanshield-worker-*` (scheduler, ingest, detection, workflow, ai). Realidad:
- `Dockerfile:43` solo lanza `uvicorn`.
- `deploy/compose/docker-compose.yml` solo tiene `postgres`, `app`, `ollama`.
- `deploy/k8s/manifests.yaml` solo tiene un Deployment de API; no hay CronJob/Deployment de `playbook_worker`, `connector_worker` ni `run_syslog`.
- Consecuencia: las ejecuciones SOAR quedan `pending` salvo que un operador ejecute el script; los conectores no se sincronizan ni se probe-health automáticamente; el syslog no escucha salvo proceso manual.

**P0 operativo:** sin esto, “SOAR durable” y “connector health” no son ciertos en la entrega desplegable.

### 6.2 Migraciones concurrentes

`Dockerfile:41-43` ejecuta `alembic upgrade head` por defecto en cada réplica (`HS_RUN_MIGRATIONS=true`). En K8s se usa Job (correcto), pero en compose o en un despliegue con réplicas sin Job hay riesgo de DDL concurrente. El comentario del Dockerfile lo reconoce, pero el default es peligroso.

### 6.3 Estado local y multi-réplica

- Evidencias en filesystem (`HS_EVIDENCE_DIR`, `Dockerfile:17`; `backend/data/evidence`). K8s exige PVC RWX para 2 réplicas; compose usa volumen local. Sin object storage, sin replicación, sin verificación de integridad al leer.
- Rate limit y sesiones en PostgreSQL (correcto para multi-réplica), pero el circuit breaker de conectores es **por proceso** (`services/connectors/runtime.py:22-56`): dos réplicas tienen umbrales independientes.
- Semáforo de IA por proceso (`services/llm/router.py:88-95,260-266`): la concurrencia real es `workers × ai_max_concurrency`, no el valor configurado.

### 6.4 Observabilidad y ciclo de vida

- `readyz` solo hace `SELECT 1` (`main.py:173-181`); no comprueba migraciones, cola, workers ni saturación. AC-110 pide `db`, `migrations`, `queue_depth`.
- Sin trazas OpenTelemetry (aunque el `.mypy_cache` revele la dependencia transitiva, no está en `pyproject`).
- Sin métricas de negocio por dominio (solo HTTP latency/count, `main.py:33-39`), sin cola de ejecuciones, sin edad de workers.
- Lifespan no drena trabajo ni cierra colas; AC-116 (SIGTERM drain ≤30 s) no se cumple de forma explícita.

---

## 7. RIESGOS DE ESCALABILIDAD

| # | Riesgo | Evidencia | Severidad | Mitigación propuesta |
| :--- | :--- | :--- | :--- | :--- |
| S-01 | Rate limit con lock de fila por usuario en **cada** request | `core/rate_limit.py:29` (`with_for_update=True`) invocado en `deps.py:257` | Alta | Bucket en memoria + sync periódico, o Redis (ADR lo excluye), o ventana deslizante SQL sin lock largo |
| S-02 | Ingesta + detección + alertas + enriquecimiento en una sola transacción | `modules/events/service.py:318-340` | Alta | Cola outbox/jobs + worker de detección; responder 202 |
| S-03 | Búsqueda `LIKE '%q%'` sobre `security_events`/`assets` | `events/router.py:566-576`; `assets/router.py:76-85` | Alta | Usar `tsvector`/`pg_trgm` ya disponibles (`0002:37-53`) o buscar en OpenSearch (ADR-006) |
| S-04 | `COUNT(*)` en cada listado | `events/router.py:579`; patrón general en routers | Media | Contadores aproximados/cursor, o `total_estimate` como ya promete el contrato |
| S-05 | Paginación `OFFSET` profunda | `core/schemas.py:72-80` | Media | Cursor por `(sort,id)` |
| S-06 | RAG: embeddings JSONB + coseno en Python sobre todos los chunks de la org | `models/ai.py:111`; `services/rag/retrieval.py` | Alta con >10⁴ chunks | Índice ANN (pgvector) o proveedor de embeddings + límite por org |
| S-07 | Evidencias en FS local con 2 réplicas | `Dockerfile:17`; PVC RWX | Media | Object storage S3-compatible o volumen compartido con verificación |
| S-08 | Circuit breaker por proceso | `runtime.py:22-56` | Media | Estado compartido en tabla `connector_health` (ya existe `status`) |
| S-09 | Llamadas HTTP de conectores/IA en el request path | `connectors/router.py:305-412`; `ai/complete` | Media | Async/cola con estado `pending`, timeouts acotados |
| S-10 | Sin outbox: fan-out in-process inexistente | `grep outbox` = 0 | Media | Implementar ADR-003 o retirar la promesa |
| S-11 | Migraciones en arranque de cada réplica | `Dockerfile:41-43` | Media | Job pre-deploy obligatorio; default `false` |
| S-12 | `security_events` sin particiones | migración inicial | Alta a >10⁷ eventos | Particionado mensual + retención por `DROP PARTITION` |
| S-13 | Pool sync por worker (10+20) sin presupuesto global | `core/db.py:20-27`; `Dockerfile:43` | Media | Documentar `workers × pool` vs `max_connections`, PgBouncer opcional |
| S-14 | Modelos IA: `AIModel`/`AIProvider` con `org_id` nullable y scope platform | `models/ai.py`; `modules/ai/providers.py` | Baja/Media | Revisar aislamiento y cuotas por org (VULN-007) |

---

## 8. RIESGOS DE SEGURIDAD Y GOBERNANZA ABIERTOS

Tomado de `.factory/SECURITY_AUDIT.md:181-205` (snapshot):

| ID | Severidad | Tema | Estado |
| :--- | :--- | :--- | :--- |
| VULN-007 | MEDIUM | Sin cuota/presupuesto IA por organización | OPEN |
| VULN-008 | MEDIUM | SSRF / transporte claro en proveedores IA | OPEN |
| VULN-009 | MEDIUM | SSRF DNS rebinding/TOCTOU en conectores/MCP | OPEN |
| VULN-010 | MEDIUM | Replay/integridad en ingesta | OPEN |
| VULN-011 | MEDIUM | Recon multi-tenant en discovery | OPEN |
| VULN-012 | MEDIUM | Carrera en claim de ejecuciones | OPEN |
| VULN-013 | MEDIUM | Falta de guardrails de autonomía (budget/freeze/blast radius) | OPEN |
| VULN-014 | MEDIUM | Integridad de auditoría (ventana de verificación) | OPEN |
| VULN-017 | MEDIUM | Lockout DoS por email | OPEN |
| VULN-018 | MEDIUM | Bypass de límite de body | OPEN |
| VULN-020 | MEDIUM | Backup/data-at-rest | OPEN |
| VULN-021 | MEDIUM | `data_region`/opt-in IA externa no implementados | OPEN |
| VULN-028 | LOW | Fingerprint de edge enumerable | **En remediación** (`0007` sin commit; auditoría aún OPEN) |

Además, gaps de gobernanza no cubiertos por la auditoría:
- A4 sin acciones y sin doble aprobación.
- Sin budgets/ventanas congeladas (la política solo decide allow/deny por nivel/riesgo).
- Sin legal hold ni retención verificable por caso.
- Sin pruebas de carga multi-tenant ni de agotamiento de pool.

---

## 9. DEUDA TÉCNICA ESTRUCTURAL (INVENTARIO)

| ID | Deuda | Evidencia | Coste de no pagarla |
| :--- | :--- | :--- | :--- |
| T-01 | Sin capa repository | 0 `repository.py`; SQL en routers | Tests de dominio frágiles, duplicación de filtros, riesgo de fuga cross-org |
| T-02 | Lógica en routers (`overview`, `organizations`) | `overview/router.py:230-455`; `organizations/router.py:141-501` | Difícil reutilizar en workers; routers de 500+ líneas |
| T-03 | Dependencia invertida services→modules | `services/playbook_engine.py:43-50` | No se puede extraer el motor SOAR a un worker sin arrastrar la app |
| T-04 | `assets` como shared kernel implícito | `iot/router.py:18`; `ot/router.py:20`; `attack_surface/service.py:17` | Cambios rompen 4 dominios; sin contrato versionado |
| T-05 | Dos “modelos” con nombre `models` | `app/models/` vs `app/modules/ai/models.py` | Confusión de imports y de responsabilidad |
| T-06 | Esquema divergente del contrato | page vs cursor; details vs fields | Clientes y tests inconsistentes |
| T-07 | Índices muertos | FTS GIN creado, no usado | Coste de escritura y falsa sensación de rendimiento |
| T-08 | `KNOWN` “23 pantallas” vs 26 reales | `README.md:208`; `App.tsx` | Documentación de producto imprecisa |
| T-09 | Tests que no existen pero se citan | `test_architecture`, `test_import_boundaries`, `test_outbox_atomicity`, `test_no_orm_leak`, `test_invitations`, `test_assets_crud`, `test_session_lifecycle` | La arquitectura no está enforced por CI |
| T-10 | Snapshot OpenAPI y api-reference desactualizados | 283 vs 284 ops; 110 endpoints documentados | Integradores fallan; soporte costoso |
| T-11 | `openapi.json` versionado como artefacto manual | `docs/openapi.json` | Drift garantizado en cada cambio de router |
| T-12 | Migración 0007 sin commit en snapshot | `git status` | Estado no reproducible; auditoría y código discrepan |

---

## 10. MATRIZ DE PRIORIDADES

### P0 — Bloquea afirmar “RC1 honesto” o “production-ready”

| # | Acción | Por qué P0 | Criterio de aceptación |
| :--- | :--- | :--- | :--- |
| P0-1 | **Verdad documental:** corregir matrices/README/arquitectura para marcar `unsupported` lo no implementado (cloud CSPM, Splunk/QRadar, EDR terceros, ticketing, SMTP, Nessus/OpenVAS/Trivy, recovery codes, SSE, cursor) | Hoy se promete capacidad inexistente | `docs/compatibility-matrix.md`, `specs/integrations/compatibility-matrix.md`, `README.md` sin filas “supported” sin adaptador; test de docs que cruce catálogo de adaptadores con matriz |
| P0-2 | **Workers desplegables:** Deployments/CronJobs para `playbook_worker`, `connector_worker`; servicio syslog opcional en compose/k8s | SOAR/connectors/syslog no operan sin cron manual | `kubectl apply` + ejecución de playbook progresa sin intervención; compose `--profile workers` |
| P0-3 | **Contrato API único:** decidir cursor/`fields`/`Idempotency-Key` e implementarlo o corregir specs/docs/tests | Rompe clientes y AC | Un solo contrato en código, `specs/api`, `docs/api-reference`, `openapi.json` regenerado en CI |
| P0-4 | **Catálogo de acciones coherente:** ocultar/rechazar `patch.apply` y `configuration.restore` si no hay capacidad, o implementar `apply_patch`/`restore_configuration` | Se ofrece autonomía que falla en ejecución | `GET /defence/actions` solo devuelve acciones con adaptador o `internal`; test de cobertura acción→capacidad |
| P0-5 | **Trazabilidad AC↔tests:** marcar AC verificados y alinear 106/44 vs 109/47; añadir AC de los gaps como `[!]` | SDD sin evidencia | Cada AC tiene test o marca `DEFERRED`; script CI valida conteos |
| P0-6 | **Rendimiento de ingesta/búsqueda:** usar FTS/trigram o particionar; sacar detección de la transacción | Riesgo directo en piloto con volumen | Test de carga: 500 ev/lote, p95 ingesta < 2 s; búsqueda sin seq scan (`EXPLAIN`) |
| P0-7 | **Seguridad abierta MEDIUM:** cerrar VULN-007/008/009/010/013/017/018 o aceptarlas formalmente con riesgo y owner | El gate dice 0 HIGH pero quedan 12 MEDIUM | `SECURITY_AUDIT.md` con estado y evidencia por VULN; tests de regresión |

### P1 — Necesario para operación enterprise y escala

| # | Acción | Criterio |
| :--- | :--- | :--- |
| P1-1 | Implementar **outbox + tabla jobs** (ADR-003) o retirar la promesa de la arquitectura y de los ADR | Eventos de dominio con entrega at-least-once y dedupe; `test_outbox_atomicity` |
| P1-2 | **SSE** `/events/stream` con backoff/dedupe y `aria-live`, o declarar polling como decisión | Endpoint `text/event-stream` + cliente con reconexión; o ADR que derogue SSE |
| P1-3 | **Refactor de fronteras:** extraer `overview` y `organizations` a services; publicar interfaz `assets` (`services/public.py` o `api.py` de módulo) | M-01/M-02/M-03 verificados por tests AST en CI |
| P1-4 | **Importadores Nessus/OpenVAS/Trivy** y export STIX/CSV de superficie | AC-25/AC-31 verificables; 207 por fila |
| P1-5 | **Informes PDF** y verificación de hash expuesta | Descarga PDF + endpoint de verificación |
| P1-6 | **Cloud CSPM real** (al menos AWS read-only) o degradar todo el dominio a roadmap | `cloud_accounts`, verify/scan, reglas deterministas, findings |
| P1-7 | **Rate limiting sin hot row** y cuotas IA por organización | Test de 1.000 req/min multi-usuario sin serialización |
| P1-8 | **RAG escalable:** pgvector o proveedor de embeddings con ANN; límites por org | Búsqueda <300 ms con 10⁵ chunks |
| P1-9 | **Frontend:** a11y automatizada (axe-core), virtualización de tablas, budgets de bundle, mapa de rutas alineado | CI axe 0 violaciones; Lighthouse/CI budget |
| P1-10 | **Observabilidad:** `/readyz` con migraciones/cola, métricas de workers, trazas | AC-110; dashboard con edad de cola y fallos de worker |
| P1-11 | **Despliegue:** `HS_RUN_MIGRATIONS=false` por defecto en imagen; Job obligatorio; PgBouncer opcional | Sin DDL concurrente; documentado en runbook |
| P1-12 | **Edge fingerprint** (0007) cerrado y auditado | Migración aplicada, VULN-028 VERIFIED, test multi-tenant |

### P2 — Madurez y alcance completo 1.x

| # | Acción |
| :--- | :--- |
| P2-1 | Invitaciones, recovery codes, listado/revocación de sesiones, historial de contraseñas |
| P2-2 | Soft delete/restore de activos, organizaciones y excepciones de riesgo con caducidad |
| P2-3 | Campañas/relaciones CTI, TTL/decaimiento, export STIX |
| P2-4 | Legal hold, manifiesto forense, export ZIP, PCAP (fuera de alcance explícito) |
| P2-5 | RoPA/DPIA, tracker NIS2 24/72 h/1 mes, PDF firmado |
| P2-6 | Versionado real de playbooks/reglas, doble aprobación, budgets, freeze, blast radius, A4 |
| P2-7 | OIDC/SCIM, HA multi-nodo, réplicas de lectura, object storage |
| P2-8 | Conectores EDR/red/SIEM/ITSM adicionales y `splunk_hec`, `ticketing_api`, `email_smtp` |

---

## 11. SECUENCIA RECOMENDADA (30/60/90)

**30 días (P0):**
1. P0-1 verdad documental + P0-4 catálogo de acciones + P0-5 trazabilidad.
2. P0-2 workers en compose/k8s.
3. P0-6 FTS/particiones + detección fuera de transacción (diseño e implementación inicial).
4. Cerrar o aceptar formalmente VULN-007/008/009/010/013/017/018.

**60 días (P1):**
5. P0-3 contrato API + OpenAPI generado en CI.
6. P1-1/P1-2 outbox/jobs o derogación de ADR; P1-3 fronteras.
7. P1-4/P1-5 importadores e informes; P1-7 rate limit; P1-10 observabilidad.
8. P1-12 edge fingerprint.

**90 días (P1/P2):**
9. P1-6 cloud CSPM (AWS primero) o roadmap público.
10. P1-8 RAG ANN; P1-9 frontend a11y/perf; P1-11 despliegue.
11. P2 identidad/forense/cumplimiento.

---

## 12. CONCLUSIÓN

HISPANSHIELD es **más sólido de lo que su documentación permite afirmar**: el núcleo SOC, la tenancy, la auditoría, el broker y el SOAR durable están implementados con criterio. Pero la capa de promesas (arquitectura, matrices, README, specs) describe una release distinta: outbox/SSE/cloud/CSPM/importadores/recovery codes/workers desplegables no están.

La corrección de mayor retorno no es escribir más features, sino **alinear el contrato público con el código** (P0-1/P0-3/P0-5), **hacer desplegable lo que ya existe** (P0-2) y **eliminar promesas de autonomía que fallan en ejecución** (P0-4). Con esas cuatro acciones, el RC1 pasa de “demo amplia” a “producto honesto y operable”; el resto (P1/P2) es escala y alcance.

---

### Resumen de 10 líneas (gaps más importantes)

1. **No existe outbox/jobs/SSE** pese a ser el eje del ADR-003 y de la arquitectura declarada.
2. **Los workers no se despliegan**: SOAR, sync de conectores y syslog dependen de scripts manuales.
3. **Cloud/CSPM, Splunk/QRadar, EDR de terceros, ticketing/SMTP y Nessus/OpenVAS/Trivy** están declarados “supported” pero no implementados.
4. **Contrato API divergente**: cursor vs page, `fields` vs `details`, sin `Idempotency-Key`.
5. **124 AC sin marcar** y conteos inconsistentes (106/44 vs 109/47; 519 vs 515 tests).
6. **Dos acciones (`patch.apply`, `configuration.restore`) sin adaptador** y **cero acciones A4**.
7. **Fronteras M-01/M-02/M-03 rotas**: 0 repositories, lógica en routers, imports cruzados e inversos.
8. **Riesgo de escala**: rate limit con lock por request, detección en la transacción de ingesta, `LIKE '%q%'` sin usar el FTS, RAG O(n) sobre JSONB.
9. **Seguridad**: recovery codes ausentes, 12 MEDIUM abiertos (SSRF, replay, lockout, guardrails de autonomía).
10. **La prioridad P0 es honestidad + operabilidad**: alinear docs, desplegar workers, unificar contrato y filtrar el catálogo de acciones.
