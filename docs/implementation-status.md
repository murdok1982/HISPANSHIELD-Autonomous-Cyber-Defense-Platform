# ESTADO DE IMPLEMENTACIÓN

- **Documento:** `docs/implementation-status.md`
- **Última actualización:** 2026-11-26
- **Regla de honestidad:** solo `VERIFIED` cuenta para el Exit Gate. `SPECIFIED` significa "contrato definido, sin código verificado". **Ninguna fila está en `VERIFIED` en este momento.**
- **Leyenda:** `NOT_STARTED` · `SPECIFIED` · `IN_PROGRESS` · `IMPLEMENTED` (código existe, sin verificación completa) · `VERIFIED` (tests + AC + gate) · `BLOCKED`

---

## 1. RESUMEN

| Estado | Filas |
| :--- | :--- |
| `NOT_STARTED` | 1 |
| `SPECIFIED` | 44 |
| `IN_PROGRESS` | 0 |
| `IMPLEMENTED` | 0 |
| `VERIFIED` | 0 |
| `BLOCKED` | 0 |
| **Total** | **45** |

Progreso del backlog: **0 / 150 tareas verificadas (0%)**.

---

## 2. TABLA DE ESTADO

| Fase | Feature | Estado | Requisitos | Tests | Resultado | Evidencia | Riesgos pendientes | Owner |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 0 | Scaffolding backend (uv, ruff, mypy, pytest) | `SPECIFIED` | `AC-117` | `TASK-001` | — | — | Entorno Python 3.12 en ruta no estándar | `@builder` |
| 0 | Scaffolding frontend (Vite, TS strict, Playwright) | `SPECIFIED` | `AC-118` | `TASK-002` | — | — | Node en ruta no estándar | `@builder` |
| 0 | Configuración, logging, errores, request-id | `SPECIFIED` | `AC-115` | `TASK-003` | — | — | Redacción de PII | `@builder` |
| 0 | Motor de BD, UoW, health | `SPECIFIED` | `AC-110` | `TASK-004` | — | — | Pool sync en workers | `@builder` |
| 0 | Migración baseline identidad | `SPECIFIED` | `AC-111` | `TASK-005` | — | — | — | `@builder` |
| 0 | Primitivas de seguridad | `SPECIFIED` | `AC-05` | `TASK-006` | — | — | Parámetros Argon2id | `@builder` |
| 0 | Cadena de auditoría | `SPECIFIED` | `AC-112` | `TASK-007` | — | — | Serialización canónica | `@builder` |
| 0 | Outbox + NOTIFY + jobs | `SPECIFIED` | `AC-110` | `TASK-008` | — | — | Throughput de NOTIFY | `@builder` |
| 0 | Middleware de seguridad | `SPECIFIED` | `AC-03` | `TASK-010` | — | — | Rate limit en multi-worker | `@builder` |
| 0 | Design tokens + primitivas UI | `SPECIFIED` | `AC-99` | `TASK-011..013` | — | — | Contraste real medido | `@ui-artisan` |
| 1 | Login, sesión, rotación | `SPECIFIED` | `AC-01`, `AC-06` | `TASK-014` | — | — | Enumeración por timing | `@builder` |
| 1 | MFA TOTP | `SPECIFIED` | `AC-02` | `TASK-015` | — | — | Anti-replay | `@builder` |
| 1 | Política de contraseñas y bloqueo | `SPECIFIED` | `AC-03`, `AC-07` | `TASK-016` | — | — | Denylist local | `@builder` |
| 1 | CSRF y tokens Bearer | `SPECIFIED` | `AC-04`, `AC-05` | `TASK-017..018` | — | — | Scopes exactos | `@builder` |
| 1 | Organizaciones, invitaciones, RBAC | `SPECIFIED` | `AC-09..AC-14` | `TASK-019..021` | — | — | Guard de último owner | `@builder` |
| 1 | App shell y flujos de auth | `SPECIFIED` | `AC-94` | `TASK-023..024` | — | — | Command palette accesible | `@ui-artisan` |
| 1 | Pantallas 22, 15, 23 | `SPECIFIED` | `AC-94` | `TASK-025..027` | — | — | Estados de permiso | `@ui-artisan` |
| 1 | Suite de aislamiento y RBAC | `SPECIFIED` | `AC-122` | `TASK-028` | — | — | Cobertura de todos los recursos | `@qa-verifier` |
| 2 | Activos, zonas, grafo, import | `SPECIFIED` | `AC-15..AC-21` | `TASK-029..034` | — | — | Grafo a escala | `@builder` |
| 2 | Superficie de ataque | `SPECIFIED` | `AC-22..AC-26` | `TASK-035..037` | — | — | Guard legal de alcance | `@builder` |
| 2 | Vulnerabilidades y scoring | `SPECIFIED` | `AC-27..AC-32` | `TASK-038..041` | — | — | Determinismo del score | `@builder` |
| 2 | Pantallas 6, 7, 8 | `SPECIFIED` | `AC-94..AC-99` | `TASK-042` | — | — | Grafo renderizable | `@ui-artisan` |
| 3 | OCSF y syslog | `SPECIFIED` | `AC-33` | `TASK-043..044` | — | — | Mapeo por fuente | `@builder` |
| 3 | Webhook HMAC e idempotencia | `SPECIFIED` | `AC-34`, `AC-35` | `TASK-045` | — | — | Replay | `@builder` |
| 3 | Event store particionado e inmutable | `SPECIFIED` | `AC-41` | `TASK-046` | — | — | Trigger y rendimiento | `@builder` |
| 3 | Búsqueda y guard de consultas | `SPECIFIED` | `AC-39` | `TASK-047` | — | — | p95 a 1M | `@builder` |
| 3 | DSL y motor de detección | `SPECIFIED` | `AC-36`, `AC-37` | `TASK-048..049` | — | — | Ventanas y estado | `@builder` |
| 3 | Alertas, correlación, retención, SSE | `SPECIFIED` | `AC-38..AC-42` | `TASK-051..053` | — | — | Dedupe exacto | `@builder` |
| 3 | Pantallas 9, 3, 2 | `SPECIFIED` | `AC-94`, `AC-101` | `TASK-054` | — | — | Stream estable | `@ui-artisan` |
| 4 | Incidentes, timeline, SLA | `SPECIFIED` | `AC-55`, `AC-56` | `TASK-055..056` | — | — | Matriz de severidad | `@builder` |
| 4 | Evidencias e informes | `SPECIFIED` | `AC-57`, `AC-58`, `AC-60` | `TASK-057..058` | — | — | Integridad en disco | `@builder` |
| 4 | CTI, STIX, TAXII, MISP, matching | `SPECIFIED` | `AC-50..AC-54` | `TASK-059..062` | — | — | TTL y decay | `@builder` |
| 4 | Forense y legal hold | `SPECIFIED` | `AC-59` | `TASK-063..064` | — | — | Export verificable | `@builder` |
| 4 | Pantallas 4, 5, 16 | `SPECIFIED` | `AC-94` | `TASK-065..067` | — | — | Visor de evidencias | `@ui-artisan` |
| 5 | Playbooks, DAG, motor durable | `SPECIFIED` | `AC-43..AC-45` | `TASK-068..070` | — | — | Reanudación exacta | `@builder` |
| 5 | Aprobaciones, compensación, dry-run | `SPECIFIED` | `AC-46..AC-49` | `TASK-071..073` | — | — | Separación de funciones | `@builder` |
| 5 | API de ejecución y pantallas 10, 19 | `SPECIFIED` | `AC-94` | `TASK-074..076` | — | — | Editor DAG accesible | `@ui-artisan` |
| 6 | Política, niveles, blast radius | `SPECIFIED` | `AC-70`, `AC-71`, `AC-73` | `TASK-078..079` | — | — | Determinismo | `@builder` |
| 6 | Broker, verificación, rollback | `SPECIFIED` | `AC-72` | `TASK-080..081` | — | — | Verificación independiente | `@builder` |
| 6 | Kill switch, budget, freeze, A4 | `SPECIFIED` | `AC-74..AC-78` | `TASK-082..084` | — | — | Halt ≤5 s | `@builder` |
| 6 | Laboratorio de autonomía | `SPECIFIED` | `AC-123` | `TASK-086` | — | — | 20/20 escenarios | `@qa-verifier` |
| 7 | Gateway IA, routing, budget, chat | `SPECIFIED` | `AC-61`, `AC-62`, `AC-67` | `TASK-088..090` | — | — | Sin LLM en runtime | `@builder` |
| 7 | Embeddings, RAG, agentes, MCP | `SPECIFIED` | `AC-63..AC-66`, `AC-69` | `TASK-091..094` | — | — | Citas y allowlist | `@builder` |
| 7 | Guardrails y estado honesto | `SPECIFIED` | `AC-65`, `AC-68` | `TASK-095..096` | — | — | Corpus de inyección | `@builder` |
| 8 | IoT, firmware, ETSI | `SPECIFIED` | `AC-79..AC-81` | `TASK-099..100` | — | — | CPE ambiguo | `@builder` |
| 8 | OT, Purdue, IEC 62443, baseline | `SPECIFIED` | `AC-82..AC-84` | `TASK-101..102` | — | — | Sin escritura PLC | `@builder` |
| 8 | Cloud y CSPM | `SPECIFIED` | `AC-85..AC-87` | `TASK-105` | — | — | Proveedor no disponible | `@builder` |
| 8 | Conectores, protocolos, edge | `SPECIFIED` | `AC-104..AC-109` | `TASK-107..111` | — | — | mTLS sin entorno real | `@builder` |
| 9 | Frameworks, controles, evaluaciones | `SPECIFIED` | `AC-88..AC-91` | `TASK-113..115` | — | — | Exactitud normativa | `@builder` |
| 9 | NIS2, GDPR, informes, auditoría | `SPECIFIED` | `AC-92`, `AC-93` | `TASK-116..117, 119` | — | — | Hash verificable | `@builder` |
| 9 | Pantallas 17, 21, 1 | `SPECIFIED` | `AC-94` | `TASK-118, 121` | — | — | Densidad ejecutiva | `@ui-artisan` |
| 10 | Integración de estados, responsive, a11y | `SPECIFIED` | `AC-95..AC-103` | `TASK-123..125` | — | — | axe en 23 rutas | `@ui-artisan` |
| 10 | SSE transversal y pasada visual | `SPECIFIED` | `AC-101` | `TASK-126..127` | — | — | Reconnect sin duplicar | `@ui-artisan` |
| 10 | E2E núcleo, autonomía, degradados | `SPECIFIED` | `AC-119` | `TASK-128..130` | — | — | Estabilidad de E2E | `@qa-verifier` |
| 10 | Rendimiento e inventario de pantallas | `SPECIFIED` | `AC-94`, `AC-118` | `TASK-131..132` | — | — | Budget de bundle | `@qa-verifier` |
| 11 | Compose, k8s, proxy | `SPECIFIED` | `AC-114` | `TASK-133..135` | — | — | Sin daemon Docker | `@builder` |
| 11 | Backup/restore, air-gap | `SPECIFIED` | `AC-113`, `AC-114` | `TASK-136..137` | — | — | Drill real | `@builder` |
| 11 | Observabilidad y hardening | `SPECIFIED` | `AC-110`, `AC-115`, `AC-116` | `TASK-138..139` | — | — | SSRF y shutdown | `@builder` |
| 11 | Secret scan, SBOM, licencias | `SPECIFIED` | `AC-120`, `AC-121` | `TASK-140..141` | — | — | Allowlist | `@builder` |
| 11 | Gates finales (backend, frontend, E2E, deps) | `SPECIFIED` | `AC-117..AC-121` | `TASK-142..145` | — | — | Flakiness | `@qa-verifier` |
| 11 | Gates de aislamiento, autonomía, inyección | `SPECIFIED` | `AC-122..AC-124` | `TASK-146..148` | — | — | Cobertura | `@qa-verifier` |
| 11 | Documentación final y auditoría | `SPECIFIED` | Exit Gate | `TASK-149..150` | — | — | 0 CRITICAL/HIGH | `@redteam-auditor` |
| — | Despliegue runtime (Docker/Ollama) | `NOT_STARTED` | `AC-114` | — | — | — | No verificable en este entorno | `@architect` |

---

## 3. QUÉ SIGNIFICA `VERIFIED` AQUÍ

Una fila pasa a `VERIFIED` solo si:
1. El código existe y no contiene placeholders.
2. El test del AC correspondiente pasa (salida registrada).
3. El gate de la fase (`scripts/verify_all.sh`) está en verde.
4. `@qa-verifier` firma con commit y fecha.
5. La evidencia está enlazada en `reports/acceptance-matrix.md`.

---

## 4. RIESGOS ABIERTOS DE IMPLEMENTACIÓN

| ID | Riesgo | Impacto | Mitigación | Owner |
| :--- | :--- | :--- | :--- | :--- |
| `IS-01` | Sin Docker/Ollama en el entorno | No se valida runtime de despliegue ni IA | Validación estática + tests con dobles + estados honestos | `@architect` |
| `IS-02` | PostgreSQL local con trust auth | Configuración no representativa | Documentar requisitos de producción | `@builder` |
| `IS-03` | Rutas de Python/Node no estándar | Scripts fallan si no se exporta PATH | `.envrc`/documentación explícita | `@builder` |
| `IS-04` | Volumen compartido | Espacio y rutas | `.gitignore`, backups | `@architect` |
| `IS-05` | Amplitud funcional (12 dominios) | Riesgo de fases incompletas | Gates por fase, backlog atómico | `@architect` |
| `IS-06` | E2E de 23 pantallas | Flakiness y tiempo | Datos deterministas, retries controlados | `@qa-verifier` |

---

## 5. PRÓXIMA ACCIÓN

Iniciar `TASK-001` (scaffolding backend) tras confirmar que el entorno exporta las rutas de Python 3.12, Node 22 y `HISPANSHIELD_DATABASE_URL` hacia PostgreSQL 18. Sin esa base, ninguna fila puede avanzar de `SPECIFIED`.
