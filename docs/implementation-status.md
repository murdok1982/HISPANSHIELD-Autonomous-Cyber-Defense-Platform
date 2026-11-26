# Estado de implementación — HISPANSHIELD RC 0.1.0

- **Fecha:** 2026-11-26
- **Estado de release:** `RELEASE CANDIDATE 1` (RC1), no GA.
- **Regla de honestidad:** `VERIFIED` exige comando ejecutado con éxito. `DEFERRED` significa ausente o simplificado y está enlazado en `.factory/TASKS.md`.
- **Backlog:** `128 / 172` tareas verificadas (incluye 22 de la ola 0.1.1); `44` aplazadas explícitamente a post-MVP; `0` pendientes sin clasificar.
- **Seguridad:** informe adversarial en `.factory/SECURITY_AUDIT.md`.

> RC1 entrega un SOC funcional de extremo a extremo: identidad y tenancy, inventario,
> vulnerabilidades, eventos/OCSF, detección, alertas, incidentes, evidencias, SOAR
> durable, autonomía gobernada, IA local, conectores, IoT/OT, edge gateway,
> cumplimiento e informes. Las capacidades avanzadas listadas como `DEFERRED` no se
> simulan ni se presentan como disponibles.

---

## 1. Evidencia ejecutada (2026-11-26)

| Gate | Comando | Resultado |
| :--- | :--- | :--- |
| Backend lint | `cd backend && ruff check app tests` | **All checks passed** |
| Backend format | `ruff format --check app tests` | **223 files already formatted** |
| Backend types | `mypy app` | **Success: no issues found in 181 source files** |
| Backend tests | `pytest -o addopts="--strict-markers"` (PostgreSQL 18) | **609 passed** |
| Edge tests | `cd edge && pytest -q` | **92 passed** |
| Frontend types | `cd frontend && tsc -b` | **exit 0** |
| Frontend build | `vite build` | **OK, route-split chunks** |
| Frontend unit | `vitest run` | **36 passed** |
| E2E screens | Playwright, 24 rutas | **2 passed** (desktop, real data, 0 console/4xx) |
| E2E critical | Playwright | **7 passed** (login, tenancy, overview, SOC/incidents, audit, admin, mobile) |
| API smoke | `scripts/smoke_api.py` | **79/79 endpoints read-only OK** |
| Dependencies | `pip-audit --skip-editable` | **No known vulnerabilities** |
| Static security | `bandit -r app` | **0 High / 0 Medium** |
| Secret scan | `.gitleaks.toml` + tracked-file audit | **No real secrets** |
| SBOM | `scripts/sbom.sh` | Generado (CycloneDX/JSON) |

---

## 2. Capacidades verificadas

| Fase | Entregado | Estado | Evidencia |
| :--- | :--- | :--- | :--- |
| 0 | FastAPI/PostgreSQL/Alembic, config validada, logging JSON, errores, auditoría append-only, migraciones, headers, design tokens, primitivas UI | `VERIFIED` | Suite backend, `test_audit_integrity`, build frontend |
| 1 | Auth Argon2id, MFA TOTP, sesiones, CSRF, API tokens, organizaciones, membresías, RBAC, perfil, app shell, login | `VERIFIED` | `test_auth`, `test_organizations`, `test_http_hardening`, E2E |
| 2 | Activos, identidades, relaciones, zonas, grafo, importación, descubrimiento pasivo/acotado, vulnerabilidades CVE/KEV/EPSS, priorización contextual, superficie de ataque | `VERIFIED` | 44 tests de dominio + UI E2E |
| 3 | Ingesta JSON/CEF/LEEF/syslog, OCSF, enriquecimiento IOC, reglas (DSL/Sigma subset), correlación, alertas, fuentes, retención, KPI | `VERIFIED` | `test_normalization`, `test_detection`, `test_events`, `test_siem`, `test_ingest_security` |
| 4 | Incidentes, máquina de estados, timeline, evidencias SHA-256/cadena de custodia, TI (STIX/TAXII/MISP/OpenCTI), MITRE, forensics, exportaciones | `VERIFIED` | `test_incidents`, `test_threat_intel`, `test_forensics` |
| 5 | Playbooks durables, validación, simulación, reintentos, compensación, aprobaciones, worker con `SKIP LOCKED`, ejecuciones | `VERIFIED` | `test_soar`, suite de durabilidad |
| 6 | Policy engine, catálogo de acciones, broker, niveles A0–A4, aprobaciones con separación de funciones, kill switches, verificación/rollback, bloqueo OT | `VERIFIED` | `test_defence`, `test_autonomy_guardrails` |
| 7 | AI gateway Ollama/vLLM/llama.cpp/OpenAI-compatible, router, uso, evaluación, RAG con citas, 16 agentes, MCP con aprobación y defensas de inyección | `VERIFIED` | `test_ai`, `test_agents`, `test_mcp`, `test_rag`, `test_prompt_safety` |
| 8 | IoT/OT pasivo, protocolos, zonas/conduits, baseline/anomalías, conectores (12 protocolos), edge gateway con cola SQLite/HMAC/replay, pantallas | `VERIFIED` | `test_iot_ot`, `test_connectors*`, `test_edge`, 92 tests edge |
| 9 | 10 marcos de cumplimiento (NIS2, CRA, GDPR, ENS, ISO 27001/27002, IEC 62443, ETSI 303 645, NIST CSF 2.0, EUCC), 105 controles, evaluaciones, evidencias, informes HTML/MD, auditoría, executive overview | `VERIFIED` | `test_frameworks`, `test_compliance`, `test_reports`, UI |
| 10 | 24 pantallas, i18n ES/EN, dark/light, command palette, responsive, estados loading/empty/error, code splitting, E2E de pantallas | `VERIFIED` | Playwright + Vitest |
| 11 | Dockerfile, Compose, K8s, CI, SBOM, backup/restore, gitleaks, pre-commit, manual de uso/integración, README, auditoría | `VERIFIED` (estático) | Manifiestos + scripts + docs |
| 12 | Ola 0.1.1: replay/nonce, discovery authz, claim atómico, guardrails, audit v2, DNS pinning, presupuestos IA, recovery codes, break-glass dual, worker durable, `/readyz` real | `VERIFIED` | `pytest` 609 passed; `.factory/SECURITY_FINDINGS.md` addendum |

---

## 3. Aplazado a post-MVP (47 tareas `[!]`)

No se presenta como implementado. Principales bloques:

- **Workflow colaborativo:** invitaciones, recovery codes MFA, listado/revocación de sesiones activas, soft delete, outbox/jobs.
- **SIEM a escala:** particiones mensuales, SSE, maintenance/legal hold, supresión avanzada de alertas.
- **Importadores adicionales:** Nessus/OpenVAS/Trivy, export STIX de superficie, excepciones de riesgo, campañas CTI/relaciones/TLP.
- **Autonomía avanzada:** doble aprobación A4 (no hay acciones A4), presupuestos de acciones, ventanas congeladas, break-glass, matriz completa de laboratorio.
- **IA/agentes:** runtime durable con reanudación, presupuestos de coste por organización.
- **IoT/OT/cloud:** checklist ETSI 13 provisiones, CPE/firmware/EOL, `required_sl` por zona, cuentas cloud/CSPM.
- **Cumplimiento:** tracker NIS2 24h/72h/1mes, RoPA/DPIA, PDF, matriz exhaustiva AC.
- **Frontend/gates:** axe-core automatizado, virtualización de tablas, E2E autónomo/degradado, Firefox/WebKit, umbral de cobertura, bundle air-gapped.

Ver `.factory/TASKS.md` para IDs, motivos y comandos de verificación.

---

## 4. Limitaciones del entorno de entrega

- **Docker/Kubernetes:** manifiestos escritos y revisados; no se ejecutaron en runtime
  porque el entorno de construcción no tenía daemon Docker. Validar en la plataforma
  destino (imagen, TLS, storage RWX, NetworkPolicy).
- **IA local:** no había runtime ni modelo en el host. La suite usa servidores HTTP
  locales simulados para probar protocolos; sin modelo real la API responde
  `503 ai_unavailable` y los agentes usan modo determinista, como se especifica.
- **Conectores externos:** probados contra servidores locales que implementan sus
  protocolos; no se certifican versiones de terceros. La matriz de compatibilidad
  declara el nivel de soporte.
- **IdP externo:** SSO OIDC federado no está habilitado por defecto; login local y
  conector administrativo Keycloak están implementados.
- **Escalado:** PostgreSQL cubre búsqueda, colas, workflows y vectores en RC1; los
  ADR documentan la migración a OpenSearch/Kafka/Qdrant/Temporal cuando se requiera.
- **Licencia:** propietaria en evaluación; revisión jurídica pendiente antes de
  distribución.

---

## 5. Veredicto

**RC1 es apta para laboratorio, piloto controlado y evaluación técnica.** No es GA,
no está certificada y no debe operarse en infraestructura crítica real sin auditoría
independiente, cierre de los 47 elementos aplazados y aprobación del CISO. El gate
de seguridad CRITICAL/HIGH se refleja en `.factory/SECURITY_AUDIT.md`.
