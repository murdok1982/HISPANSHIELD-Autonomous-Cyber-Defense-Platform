# Estado de implementación — HISPANSHIELD 0.1.2

- **Fecha:** 2026-11-26
- **Estado de release:** `RELEASE CANDIDATE 0.1.2`, no GA.
- **Regla de honestidad:** `VERIFIED` exige comando ejecutado con éxito en este
  entorno. `DEFERRED` significa ausente o parcial y está enlazado en
  `.factory/TASKS.md`. `IMPLEMENTED` no se presenta como `VERIFIED`.
- **Backlog:** `138 / 176` tareas verificadas; `37` aplazadas/bloqueadas; `1` en
  progreso (`TASK-008`, outbox sin `LISTEN/NOTIFY` ni tabla `jobs` separada).
- **Criterios de aceptación:** `70` verificados, `32` parciales, `22` no
  verificados. Matriz reproducible en `.factory/AC_TRACEABILITY.md`.
- **Fuente de métricas:** `python3 scripts/factory_metrics.py` →
  `.factory/EVIDENCE/METRICS.json`.

> Esta entrega evoluciona RC1 sin reescribirlo: conserva el monolito modular, añade
> outbox transaccional, SSE, auditoría HMAC v3, cursor pagination,
> `Idempotency-Key`, setup/invitaciones y un gate de validación de despliegue.
> No convierte en soportadas las capacidades que siguen ausentes (CSPM cloud,
> importadores Nessus/OpenVAS/Trivy, legal hold, particiones, A4).

---

## 1. Evidencia ejecutada en esta ola

| Gate | Comando | Resultado |
| :--- | :--- | :--- |
| Métricas | `python3 scripts/factory_metrics.py` | 650 tests backend, 92 edge, 23 pantallas de navegación, 26 de contenido, 305 operaciones OpenAPI, 12 adaptadores |
| Backend lint | `uvx ruff@0.11.10 check app tests` | Ver `.factory/EVIDENCE/BACKEND_TEST_RUN.md` |
| Backend format | `uvx ruff@0.11.10 format --check app tests` | Ver evidencia |
| Backend types | `uvx mypy@1.15.0 app` | Ver evidencia |
| Backend tests | `python -m pytest -o addopts="" -q` (PostgreSQL 18) | **650 passed** (ver evidencia) |
| Edge tests | `cd edge && python -m pytest -q -o addopts=""` | **92 passed** |
| Frontend types | `node node_modules/typescript/bin/tsc -b --force` | exit 0 |
| Frontend build | `node node_modules/vite/bin/vite.js build` | OK, route-split chunks |
| Frontend unit | `node node_modules/vitest/vitest.mjs run` | **36 passed** |
| K8s render+validate | `./deploy/k8s/render.sh /tmp/values.env \| python3 scripts/validate_deploy.py` | **PASS** (plantilla sin renderizar: **FAIL esperado**) |
| E2E Playwright | `npx playwright test` | **NOT RUN** en este host (sin navegadores instalados) |
| pip-audit / bandit / gitleaks | — | **NOT RUN** en esta ola; no se reclaman como verdes |
| Docker/Kubernetes runtime | — | **NOT RUN**; solo validación estática/render |

---

## 2. Capacidades verificadas

| Fase | Entregado | Estado | Evidencia |
| :--- | :--- | :--- | :--- |
| 0 | FastAPI/PostgreSQL/Alembic, config validada, logging JSON, errores, auditoría append-only, migraciones, headers, design tokens, primitivas UI | `VERIFIED` | suite backend, `test_audit_integrity`, build frontend |
| 1 | Auth Argon2id, MFA TOTP + recovery codes, sesiones activas con listado/revocación, CSRF, API tokens, organizaciones, invitaciones single-use (72 h), RBAC, `/setup` con A0, política de contraseñas pública | `VERIFIED` | `test_auth`, `test_auth_policy`, `test_invitations`, `test_setup`, UI `ActiveSessionsPanel` |
| 2 | Activos, identidades, relaciones, zonas, grafo, importación, descubrimiento con autorización, vulnerabilidades CVE/KEV/EPSS, priorización contextual, superficie de ataque, cursor pagination | `VERIFIED` (FTS/benchmark pendiente) | 44 tests de dominio, `test_cursor_pagination` |
| 3 | Ingesta JSON/CEF/LEEF/syslog, OCSF, enriquecimiento IOC, reglas, correlación, alertas, fuentes, retención, KPI, SSE `/events/stream` | `VERIFIED` (particionado pendiente) | `test_normalization`, `test_detection`, `test_events`, `test_siem`, `test_ingest_security`, `test_sse` |
| 4 | Incidentes, timeline, evidencias SHA-256/cadena de custodia, TI (STIX/TAXII/MISP/OpenCTI), MITRE, forensics, exportaciones | `VERIFIED` (legal hold pendiente) | `test_incidents`, `test_threat_intel`, `test_forensics` |
| 5 | Playbooks durables, validación, simulación, reintentos, compensación, aprobaciones, worker `SKIP LOCKED`, ejecuciones, idempotencia de pasos | `VERIFIED` | `test_soar`, `test_playbook_claim` |
| 6 | Policy engine, catálogo A0–A3, broker, aprobaciones, kill switches, presupuestos/cooldown/freeze/blast radius, verificación/rollback, bloqueo OT | `VERIFIED` (A4 ausente por diseño) | `test_defence`, `test_autonomy_guardrails`, `test_policy_guardrails` |
| 7 | AI gateway Ollama/vLLM/llama.cpp/OpenAI-compatible, router, uso, evaluación, RAG con citas, 16 agentes, MCP gobernado, defensas de inyección | `VERIFIED` (runtime durable de agentes pendiente) | `test_ai`, `test_agents`, `test_mcp`, `test_rag`, `test_prompt_safety` |
| 8 | IoT/OT pasivo, protocolos, zonas/conduits, baseline/anomalías, conectores (12 adaptadores), edge gateway con SQLite WAL/HMAC/replay | `VERIFIED` (checklist ETSI/CPE pendiente) | `test_iot_ot`, `test_connectors*`, `test_edge`, 92 edge |
| 9 | 10 marcos, 105 controles, evaluaciones, evidencias, informes HTML/MD, auditoría, executive overview | `VERIFIED` (PDF/tracker NIS2 pendiente) | `test_frameworks`, `test_compliance`, `test_reports` |
| 10 | 23 pantallas de navegación, i18n ES/EN, dark/light, command palette, responsive, estados loading/empty/error, code splitting, SSE en Monitorización, sesiones activas | `VERIFIED` (axe/Playwright pendientes) | `tsc`, `vite build`, `vitest`; `useEventStream` |
| 11 | Dockerfile, Compose con worker, plantilla K8s renderizable, validación anti-placeholder, CI, SBOM, backup/restore, gitleaks config, pre-commit, manuales | `VERIFIED` (estático; runtime no ejecutado) | `validate_deploy.py`, CI job |
| 12 | Ola 0.1.1: replay/nonce, discovery authz, claim atómico, guardrails, audit v2, DNS pinning, presupuestos IA, recovery codes, break-glass dual, worker durable, `/readyz` | `VERIFIED` | `pytest`, `.factory/SECURITY_FINDINGS.md` |
| 13 | Ola 0.1.2: auditoría HMAC v3 + checkpoints, outbox + DLQ + consumidor de notificaciones, SSE, cursor, `Idempotency-Key`, setup A0, invitaciones, gate K8s, métricas/AC trazables | `VERIFIED` | `test_audit_hmac`, `test_outbox`, `test_sse`, `test_cursor_pagination`, `test_idempotency`, `test_setup`, `test_invitations` |

---

## 3. Aplazado / parcial (37 tareas `[!]` + 1 `[~]`)

No se presenta como implementado:

- **Durabilidad:** `LISTEN/NOTIFY` y tabla `jobs` separada; outbox ya existe con
  leases/retries/DLQ (`TASK-008` en progreso).
- **Escala SIEM:** particiones mensuales, mantenimiento, legal hold,
  benchmark 100k eventos/p95, FTS real en búsquedas.
- **Vulnerabilidades:** importadores Nessus/OpenVAS/Trivy, excepciones de riesgo.
- **Cloud/CSPM:** cuentas cloud, credenciales, reglas CSPM (la vista `/cloud` es
  postura derivada, no CSPM).
- **Autonomía:** A4 (sin acciones), matriz completa de laboratorio, concurrencia
  por organización.
- **IA/agentes:** runtime durable de agentes con reanudación.
- **IoT/OT:** checklist ETSI 13 provisiones, CPE/firmware/EOL, `required_sl`.
- **Cumplimiento:** tracker NIS2 24 h/72 h/1 mes, RoPA/DPIA, PDF.
- **Frontend/gates:** axe-core, E2E Firefox/WebKit, gate de cobertura, air-gap,
  benchmark de rendimiento frontend.
- **Operación:** restauración de backup ejecutada, air-gap real, Docker/K8s
  runtime, escaneos de dependencias/secretos ejecutados en esta ola.

Ver `.factory/TASKS.md` para IDs, motivos y comandos de verificación.

---

## 4. Limitaciones del entorno de entrega

- **Docker/Kubernetes:** plantilla renderizada y validada; no se ejecutó un
  clúster real. El manifiesto sin renderizar se rechaza por diseño.
- **Playwright:** no se ejecutó en este host. La suite existe y el build/unit
  tests frontend están verdes.
- **pip-audit / bandit / gitleaks:** configuración presente; no ejecutados en
  esta ola. No se afirma “sin vulnerabilidades” sin esa evidencia.
- **Backup/restore:** scripts presentes; no se ejecutó una restauración completa
  en una instancia aislada.
- **Base de datos de test:** PostgreSQL 18 local en `127.0.0.1:55432`; se creó
  `hispanshield_test` para poder ejecutar la suite.
