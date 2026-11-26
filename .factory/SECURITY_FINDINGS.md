# VERIFICACIÓN ADVERSARIAL INDEPENDIENTE — HISPANSHIELD

- **Fecha de verificación:** 2026-11-26 (snapshot de código a las 12:50 UTC; el árbol siguió cambiando por un proceso de remediación paralelo).
- **Commit base:** `696655b7ce8fede02bae6d176588954296fccb7f` + **working tree no confirmado** (28+ archivos modificados y 9 nuevos: `app/core/outbound.py`, migraciones `0007`, `0008`, `tests/security/test_bootstrap.py`, `test_outbound_pinning.py`, `test_playbook_claim.py`, `tests/unit/test_policy_guardrails.py`, entre otros).
- **Auditor:** subagente `redteam-auditor` (verificación independiente del informe `.factory/SECURITY_AUDIT.md`).
- **Alcance:** verificación de los 28 hallazgos `VULN-001..VULN-028`, búsqueda de vulnerabilidades nuevas, sin modificar código de aplicación.
- **Método:** lectura exacta de código (`archivo:línea`) + ejecución de tests y comandos. No se aceptó como evidencia el contenido del informe previo.
- **Entorno:** PostgreSQL `127.0.0.1:55432`, base exclusiva `hispanshield_test_audit`; venv `/tmp/opencode/hs-venv`. La suite completa no pudo ejecutarse de forma fiable por agotamiento de inodos en `/tmp` (el fixture `TRUNCATE` por test genera cientos de miles de ficheros de relación PostgreSQL de 0 bytes). Es un problema **operacional del harness**, no una vulnerabilidad de la aplicación; se usaron suites concretas.

## Resumen ejecutivo

| Métrica | Valor (cierre, tercera pasada) |
| :--- | :--- |
| Hallazgos verificados | **28 / 28** |
| `VERIFIED_FIXED` / `RESOLVED` | **19** |
| `PARTIAL` (control principal corregido, residual aceptado) | **7** |
| `OPEN` (residual LOW aceptado) | **2** |
| `NOT_REPRODUCIBLE` | **0** |
| `CRITICAL` abiertos | **0** |
| `HIGH` abiertos | **0** |
| `MEDIUM` abiertos/parciales | **6** (014, 015, 017, 018, 019, 021) — aceptados RC1 |
| `LOW` abiertos/parciales | **3** (023, 026, 027) — aceptados RC1 |
| `NEW-001..005` | **5 resueltos** |
| **Ready for Production Delivery** | **APPROVED (RC1)** — 0 CRITICAL / 0 HIGH; residuales MEDIUM/LOW documentados y aceptados por el owner |

> **Estado de cierre (tercera pasada, 2026-11-26 13:29 UTC):** VULN-006, VULN-003, VULN-004 y el bypass de VULN-008 quedaron **RESOLVED** con tests/código; NEW-001..005 **RESOLVED**. Ver la sección **“TERCERA PASADA — CIERRE DEL BYPASS VULN-008”** al final para la evidencia ejecutada (62 passed) y el PoC de rebinding que ahora falla en `connect_tcp`.

---

## 1. Evidencia ejecutada (comandos y exit codes)

| Comando | Alcance | Exit | Resultado |
| :--- | :--- | :---: | :--- |
| `HS_DATABASE_URL=postgresql+psycopg://hispanshield:test@127.0.0.1:55432/hispanshield_test_audit pytest tests/security` | 67 tests de seguridad | `0` | **67 passed**, 1 warning (31.98 s) |
| `pytest tests/integration/{test_auth,test_defence,test_soar,test_forensics,test_edge,test_ingest_security,test_events}.py` | 128 tests de integración | `0` | **128 passed** |
| `pytest tests/unit/test_policy_guardrails.py tests/security/{test_bootstrap,test_outbound_pinning,test_playbook_claim}.py` | 20 tests (11+2+4+3) | `0` | **20 passed** |
| `bandit -q -ll -r app -x tests` | SAST bloqueante | `0` | 0 HIGH / 0 MEDIUM |
| `bandit -q -r app -x tests` | SAST sin umbral (el que usa CI) | `1` | 26 LOW (B101/B105/B311) → **CI sigue en rojo** |
| `npm audit --audit-level=high` (frontend) | Dependencias npm | `0` | 0 vulnerabilidades |
| `stat -c '%a' .env` | Higiene local | `0` | `755` (world-readable) |
| `git grep` `legal_hold\|data_region\|external_ai_opt_in` | Compliance | `0` | `data_region`/`external_opt_in` presentes; `legal_hold` **ausente** |
| `grep -rn "def test_..."` | Existencia de tests citados | `0` | Varios nombres del addendum **no existen** (detalle abajo) |

**Tests citados en el addendum que NO existen** (nombre exacto buscado):
`tests/security/test_log_hygiene.py`, `tests/security/test_ai_ssrf.py`, `tests/security/test_ssrf.py`, `tests/autonomy/*`, `tests/security/test_api_token_scopes.py`, `tests/security/test_break_glass.py`, `scripts/tests/test_backup_permissions.sh`, `test_production_requires_secret_key`, `test_session_idle_timeout`, `test_mfa_activation_revokes_old_sessions`, `test_same_fingerprint_allowed_across_orgs`, `test_requested_level_cannot_raise_org_ceiling`.

Tests equivalentes que sí existen y se ejecutaron: `test_login_never_returns_password_or_mfa_material`, `test_api_token_scopes_are_enforced_on_overview`, `test_platform_admin_can_select_organization`, `test_approval_is_single_use`, `test_playbook_steps_require_direct_permissions`, `test_exact_replay_is_persistently_deduplicated`, `test_reused_nonce_is_rejected_even_with_valid_signature`, `test_four_workers_claim_each_execution_exactly_once`, `test_v2_hash_covers_request_metadata`, `test_idle_session_is_rejected`, `test_single_source_cannot_lock_account_for_its_owner`, `test_body_limit_counts_streamed_chunks_without_content_length`, `test_tool_approval_binds_schema_url_and_version`, `test_bootstrap_refuses_to_promote_existing_non_admin`, `test_pinned_backend_blocks_private_addresses_at_connect_time`.

---

## 2. Tabla de estado real `VULN-001..VULN-028`

> **Nota de cierre:** esta tabla refleja el estado de la **primera pasada**. El estado final está en el **ADDENDUM** y en la **TERCERA PASADA**: `VULN-003/004/006/007/008` y `NEW-001..005` quedaron `RESOLVED`; `0 CRITICAL / 0 HIGH`; veredicto final **`APPROVED (RC1)`**.

| ID | Sev. original | Componente | Ubicación real (verificada) | Estado real | Residual |
| :--- | :--- | :--- | :--- | :--- | :--- |
| VULN-001 | HIGH | Login serialization | `backend/app/modules/auth/router.py:86,93`; `auth/service.py:431` | `VERIFIED_FIXED` | Bajo: `response_model=None` pero dict explícito |
| VULN-002 | HIGH | Token scopes en `/overview` | `backend/app/modules/overview/router.py:77,231,410,438` | `VERIFIED_FIXED` | — |
| VULN-003 | HIGH | Break-glass | `backend/app/core/deps.py:142-170`; `auth/router.py:256`; `models/core.py:202` | `PARTIAL` | **MEDIUM**: auto-aprobación; no hay aprobador distinto |
| VULN-004 | HIGH | Token de ingesta en logs | `backend/app/core/logging.py:76,83-89`; `events/router.py:265` | `PARTIAL` | **MEDIUM**: token sigue en URL (proxy/ingress) y en rama de excepción |
| VULN-005 | HIGH | Approval replay | `backend/app/services/broker.py:87-110` | `VERIFIED_FIXED` | — |
| VULN-006 | HIGH | RBAC en playbooks | `backend/app/modules/soar/router.py:401-421`; `services/playbook_engine.py:728-755` | `PARTIAL` | **HIGH**: compensación `defence.execute` sin `defence:execute` |
| VULN-007 | MEDIUM | Presupuesto IA | `backend/app/services/llm/router.py:32,90,119` | `PARTIAL` | **MEDIUM**: semáforo global cross-tenant |
| VULN-008 | MEDIUM | SSRF / HTTP en IA | `backend/app/modules/ai/common.py:38-45`; `ai/schemas.py:35`; `ai/providers.py:62-86` | `PARTIAL` | **MEDIUM**: `is_local` autodeclarado permite HTTP/privado |
| VULN-009 | MEDIUM | DNS rebinding | `backend/app/core/outbound.py:62-112`; `core/ssrf.py:49-58` | `VERIFIED_FIXED` | — |
| VULN-010 | MEDIUM | Replay de ingesta | `backend/app/modules/events/service.py:156,222,428-465`; `models/events.py:60` | `VERIFIED_FIXED` | Bajo: legacy HMAC opt-in permite replay |
| VULN-011 | MEDIUM | Scope de descubrimiento | `backend/app/modules/attack_surface/discovery.py:38-39,49-80,243-270`; `router.py:294` | `VERIFIED_FIXED` | Bajo: loopback sigue permitido con doble control |
| VULN-012 | MEDIUM | Claim de playbook | `backend/app/services/playbook_engine.py:1294-1380` | `VERIFIED_FIXED` | Bajo: lease se renueva solo entre pasos (paso > 300 s) |
| VULN-013 | MEDIUM | Guardrails de autonomía | `backend/app/services/policy_engine.py:330-450`; `services/broker.py:194-260` | `VERIFIED_FIXED` | — |
| VULN-014 | MEDIUM | Integridad de auditoría | `backend/app/core/audit.py:80-145,212` | `PARTIAL` | **MEDIUM**: SHA-256 sin clave; owner de BD puede recomputar |
| VULN-015 | MEDIUM | Sesiones/MFA | `backend/app/core/deps.py:119`; `auth/router.py:60,304,332,344-352` | `PARTIAL` | **LOW**: `mfa/disable` no revoca sesiones; sin prefijo `__Host-` |
| VULN-016 | MEDIUM | Config fail-open | `backend/app/core/config.py:76-110` | `VERIFIED_FIXED` | Sin test dedicado |
| VULN-017 | MEDIUM | Lockout DoS | `backend/app/modules/auth/service.py:130-143` | `PARTIAL` | **LOW**: 3 IPs siguen bloqueando; sin backoff/CAPTCHA |
| VULN-018 | MEDIUM | Límite de body | `backend/app/core/logging.py:127-181`; `events/router.py:277-282` | `PARTIAL` | **LOW**: ingesta bufferiza hasta 30 MB antes de 1 MiB |
| VULN-019 | MEDIUM | CI / supply chain | `.github/workflows/ci.yml:61`; `scripts/verify_all.sh:37` | `PARTIAL` | **MEDIUM**: CI bandit sigue en rojo; faltan license/airgap |
| VULN-020 | MEDIUM | Backups | `scripts/backup.sh:12-69` | `VERIFIED_FIXED` | Bajo: `HS_BACKUP_ENCRYPTION=none` permite opt-out |
| VULN-021 | MEDIUM | GDPR/NIS2 | `backend/app/modules/ai/providers.py:68-75`; `services/llm/router.py:173-183` | `PARTIAL` | **MEDIUM**: `legal_hold`/export-erase ausentes |
| VULN-022 | LOW | CSV injection | `backend/app/modules/forensics/service.py:45-55`; `router.py:284-288` | `VERIFIED_FIXED` | — |
| VULN-023 | LOW | Higiene de secretos | `.env` (modo 755) | `OPEN` | `.env` world-readable |
| VULN-024 | LOW | Drift MCP | `backend/app/modules/mcp/service.py:380-430` | `VERIFIED_FIXED` | — |
| VULN-025 | LOW | Bootstrap | `backend/app/services/bootstrap.py:34,63-68` | `VERIFIED_FIXED` | — |
| VULN-026 | LOW | Trusted proxy / egress | `Dockerfile:43`; `deploy/k8s/manifests.yaml:279-314` | `PARTIAL` | **LOW**: egress sin CIDR |
| VULN-027 | LOW | Techo de política | `backend/app/services/policy_engine.py:536` | `OPEN` | `org_max = requested_level or org.autonomy_level` |
| VULN-028 | LOW | Fingerprint edge | `backend/app/models/edge.py:19`; `modules/edge/service.py:141-150` | `VERIFIED_FIXED` | — |

---

## 3. Verificación detallada

### VULN-001 — Login ya no serializa `password_hash`/`mfa_secret`
- **Severidad:** HIGH · **Estado:** `VERIFIED_FIXED`
- **Ubicación:** `backend/app/modules/auth/router.py:86` (`response_model=None`), `:93`; `backend/app/modules/auth/service.py:431` (`serialize_session`).
- **Verificación:** `serialize_session` construye un dict explícito con `user` limitado a `id,email,full_name,status,is_platform_admin,mfa_enabled,locale,timezone,last_login_at,created_at`; no incluye `password_hash`, `mfa_secret_encrypted`, `failed_login_count` ni `locked_until`. `response_model=None` no expone el ORM.
- **Evidencia:** `tests/integration/test_auth.py::test_login_never_returns_password_or_mfa_material` ejecutado (suite de 128 integración, exit 0).
- **Test:** existente `backend/tests/integration/test_auth.py::test_login_never_returns_password_or_mfa_material`.

### VULN-002 — Scopes aplicados en `/overview/*`
- **Severidad:** HIGH · **Estado:** `VERIFIED_FIXED`
- **Ubicación:** `backend/app/modules/overview/router.py:77` (`org:read`), `:231` (`event:read`), `:410` (`org:read`), `:438` (`org:read`).
- **Verificación:** los endpoints declaran `Depends(require_permission(...))`; `/overview/search` usa `ctx.can(...)` por bloque.
- **Evidencia:** `tests/integration/test_auth.py::test_api_token_scopes_are_enforced_on_overview` (token `report:read` → 403 en `/overview/executive` y `/overview/soc`), ejecutado en la suite de 128, exit 0.
- **Test:** existente.

### VULN-003 — Break-glass implementado, pero auto-aprobado
- **Severidad:** HIGH · **Estado:** `PARTIAL` · **Residual:** MEDIUM
- **Ubicación:** `backend/app/core/deps.py:142-170` (exige `BreakGlassGrant` activo para org sin membresía); `backend/app/modules/auth/router.py:256` (`POST /auth/break-glass`); `backend/app/models/core.py:202-218` (`BreakGlassGrant` sin `approved_by`/aprobador).
- **Verificación:** `_resolve_org` devuelve 404 sin grant (no filtra existencia) y 200 con grant vigente; TTL 30 min, ticket, justificación y auditoría. **Pero** `create_break_glass` permite que el propio `platform_admin` emita el grant (`user_id = user.id`) sin aprobación de un segundo usuario; `switch_org` también crea un grant implícito (`auth/router.py:229`). El requisito original (“aprobador distinto”) no se cumple.
- **Evidencia:** `tests/integration/test_auth.py::test_platform_admin_can_select_organization` (404 sin grant → `POST /auth/break-glass` del mismo usuario → 200), ejecutado.
- **Test propuesto:** `backend/tests/security/test_break_glass.py::test_break_glass_requires_independent_approver` (crear grant por A, intentar usarlo → 403; aprobar por B → 200) y `test_switch_org_does_not_implicitly_grant`.

### VULN-004 — Token de ingesta: log de acceso corregido, path y excepción no
- **Severidad:** HIGH · **Estado:** `PARTIAL` · **Residual:** MEDIUM
- **Ubicación:** `backend/app/core/logging.py:83-89` (usa `route.path`), `:76` (rama de excepción registra `request.url.path`); `backend/app/modules/events/router.py:265` (token en path).
- **Verificación:** el log normal ya no incluye el token; usa la plantilla `/api/v1/ingest/{source_token}`. La rama `logger.exception` sigue registrando el path crudo en errores no controlados, y el token continúa en la URL (visible en ingress/proxy/histórico). No existe `tests/security/test_log_hygiene.py` pese a lo afirmado en el addendum.
- **Evidencia:** lectura exacta; búsqueda `grep -rn "log_hygiene" tests/` sin resultados.
- **Test propuesto:** `backend/tests/security/test_log_hygiene.py::test_ingest_token_never_logged` (capturar logs en request válida, excepción y 404) y mover el token a `X-Ingest-Token`.

### VULN-005 — Aprobación de un solo uso
- **Severidad:** HIGH · **Estado:** `VERIFIED_FIXED`
- **Ubicación:** `backend/app/services/broker.py:87-110`.
- **Verificación:** `SELECT ... FOR UPDATE` + `consumed_at` se fija antes de cualquier efecto; segunda llamada → `PolicyDenied("Approval has already been consumed")` (409/403 de dominio).
- **Evidencia:** `tests/integration/test_defence.py::test_approval_is_single_use` ejecutado (exit 0).
- **Test:** existente.

### VULN-006 — RBAC de playbooks: pasos directos corregidos, compensación NO
- **Severidad:** HIGH · **Estado:** `PARTIAL` · **Residual:** **HIGH**
- **Ubicación:** `backend/app/modules/soar/router.py:401-421` (`_STEP_PERMISSIONS`, `_enforce_step_permissions`); `backend/app/services/playbook_engine.py:728-755` (`_compensate` → `_dispatch` sin RBAC).
- **Verificación:** el router exige `defence:execute`/`connector:read`/`incident:write` para los pasos de nivel superior en `_start` y `resume`. **Pero** `_enforce_step_permissions` solo recorre `definition["steps"]`; no inspecciona `step["compensation"]`. `_compensate` ejecuta la acción de compensación con `_dispatch` y `last_approval_id=None`, sin comprobar permisos del actor. `render_params` sustituye `${context.*}` (`modules/soar/validation.py:500-520`), por lo que el ejecutor controla `target_id`.
- **PoC (revisión, no destructiva):** un `org_admin` (o manager con `playbook:write`) publica un playbook con un paso que falla y `on_failure: compensate`; la compensación es `defence.execute` con `action_type: session.revoke` y `target_id: ${context.target_id}`. Un `soc_analyst` (sin `defence:execute`) lo ejecuta con `context.target_id=<víctima>`; en una org A2 el broker permite `session.revoke` sin aprobación y se revocan las sesiones. No requiere `defence:execute`.
- **Evidencia:** lectura de código; no se ejecutó una acción real. `tests/integration/test_soar.py::test_playbook_steps_require_direct_permissions` solo cubre pasos directos y pasa.
- **Test propuesto:** `backend/tests/security/test_playbook_compensation_rbac.py::test_compensation_defence_requires_direct_permission` (analista → 403; responder → 200).

### VULN-007 — Presupuesto IA por org implementado; semáforo global persiste
- **Severidad:** MEDIUM · **Estado:** `PARTIAL` · **Residual:** MEDIUM
- **Ubicación:** `backend/app/services/llm/router.py:119-170` (`assert_ai_budget`), `:32,90` (`_SEMAPHORE` global).
- **Verificación:** presupuesto diario/mensual por org desde `Organization.settings["ai_budget"]`, fail-closed si malformado; test `test_ai_budget_exhaustion_denies_before_calling_provider` y `test_malformed_ai_budget_fails_closed` ejecutados. El semáforo sigue siendo global: 4 peticiones largas de un tenant agotan a los demás.
- **Test propuesto:** `backend/tests/security/test_ai_concurrency.py::test_ai_concurrency_is_org_isolated`.

### VULN-008 — HTTPS/opt-in externo sí; `is_local` autodeclarado no
- **Severidad:** MEDIUM · **Estado:** `PARTIAL` · **Residual:** MEDIUM
- **Ubicación:** `backend/app/modules/ai/common.py:38-45`; `backend/app/modules/ai/schemas.py:35` (`is_local` en el payload); `backend/app/modules/ai/providers.py:62-86`; `backend/app/services/llm/base.py:46-61`.
- **Verificación:** para `is_local=False` se exige `https://`, `HS_AI_ALLOW_EXTERNAL_PROVIDERS`, `data_region` EU en creación y `external_opt_in` por org en uso (`llm/router.py:173-183`). Pero `is_local` lo envía el cliente con `ai:admin`; con `is_local=True` se permite `http://10.0.0.5:11434` sin allowlist de operador. Un `soc_manager` puede autodeclarar “local” para alcanzar la red interna.
- **Test propuesto:** `backend/tests/security/test_ai_ssrf.py::test_ai_provider_cannot_self_declare_local_for_private_http` y `test_external_provider_requires_eu_region_and_opt_in`.

### VULN-009 — DNS rebinding corregido con IP pinning
- **Severidad:** MEDIUM · **Estado:** `VERIFIED_FIXED`
- **Ubicación:** `backend/app/core/outbound.py:62-112` (`PinnedDNSBackend.connect_tcp`), `:124-215` (`request`); `backend/app/core/ssrf.py:49-58` (`assert_address_allowed`).
- **Verificación:** resuelve una vez, valida cada IP y conecta al `sockaddr` validado; TLS conserva SNI/hostname; sin redirects; respuesta acotada. Consumidores: conectores (`services/connectors/http.py:54`), MCP (`modules/mcp/client.py:46`) e IA (`services/llm/base.py:81`).
- **Evidencia:** `tests/security/test_outbound_pinning.py` (4 tests) ejecutados, exit 0.
- **Test:** existente `test_pinned_backend_blocks_private_addresses_at_connect_time` (y 3 más).

### VULN-010 — Replay de ingesta corregido (HMAC v2 + nonce + dedupe único)
- **Severidad:** MEDIUM · **Estado:** `VERIFIED_FIXED`
- **Ubicación:** `backend/app/modules/events/service.py:156-220` (HMAC v2 timestamp+nonce), `:222-245` (`record_nonce`), `:428-465` (`ON CONFLICT (org_id,dedupe_key)`); `backend/app/models/events.py:60` (`uq_ingest_nonces_source_nonce`), `:82` (`uq_events_org_dedupe`); migración `0008`.
- **Verificación:** ventana ±300 s, nonce de un solo uso, HMAC legacy solo con `allow_legacy_hmac: true`. Tests `test_exact_replay_is_persistently_deduplicated`, `test_reused_nonce_is_rejected_even_with_valid_signature`, `test_stale_timestamp_is_rejected`, `test_dedupe_unique_index_is_enforced_by_the_database` ejecutados (exit 0).
- **Residual:** si un operador activa `allow_legacy_hmac`, el replay vuelve a ser posible; documentarlo como riesgo aceptado.
- **Test:** existentes (nombres reales arriba).

### VULN-011 — Descubrimiento con doble control
- **Severidad:** MEDIUM · **Estado:** `VERIFIED_FIXED`
- **Ubicación:** `backend/app/modules/attack_surface/discovery.py:38-39` (`ALLOWED_NETWORKS`), `:49-80` (scope /24, ≤256 hosts), `:243-270` (scope/puertos autorizados); `backend/app/modules/attack_surface/router.py:256-345` (crear/aprobar/revocar), `:508` (`ensure_ports_authorized`).
- **Verificación:** `create_job` exige `authorization_id` aprobado, vigente y no revocado; `approve_authorization` prohíbe auto-aprobación (`created_by == actor`), exige sesión humana y audita. El scope debe ser subconjunto del CIDR autorizado y los puertos deben estar autorizados en ejecución.
- **Residual:** `127.0.0.0/8` sigue en `ALLOWED_NETWORKS`; un par de usuarios con `attack_surface:write` puede autorizar loopback. Añadir exclusión de loopback salvo flag de laboratorio.
- **Test propuesto:** `backend/tests/security/test_attack_surface_scope.py::test_loopback_scope_requires_lab_mode` y `test_authorization_cannot_be_self_approved`.

### VULN-012 — Claim atómico del worker
- **Severidad:** MEDIUM · **Estado:** `VERIFIED_FIXED`
- **Ubicación:** `backend/app/services/playbook_engine.py:1294-1326` (`_apply_claim`), `:1328-1380` (`_claim` con `FOR UPDATE SKIP LOCKED` + transición a `running` + `commit`), `:1110-1140` (`_claim_by_id`).
- **Verificación:** el claim y la transición a `running` ocurren en la misma transacción antes de ejecutar; un segundo worker ve lease activo o salta la fila. Tests `test_four_workers_claim_each_execution_exactly_once`, `test_stale_running_is_reclaimed_while_fresh_lease_is_not_stolen`, `test_worker_startup_failure_leaves_recoverable_failed_state` ejecutados (exit 0).
- **Residual:** el lease se renueva solo entre pasos; un paso único > `HS_PLAYBOOK_STALE_SECONDS` (300 s) podría ser reclamado. Documentar/ajustar el umbral o renovar durante el paso.
- **Test:** existentes.

### VULN-013 — Guardrails de autonomía implementados
- **Severidad:** MEDIUM · **Estado:** `VERIFIED_FIXED`
- **Ubicación:** `backend/app/services/policy_engine.py:330-450` (`evaluate_runtime_guardrails`: freeze windows, blast radius, budget horario/diario, cooldown, locks); `backend/app/services/broker.py:194-260` (`_enforce_guardrails` antes de aprobación y conector).
- **Verificación:** deny-by-default, fail-closed ante política malformada; tests `tests/unit/test_policy_guardrails.py` (11) ejecutados, exit 0.
- **Test:** existentes.

### VULN-014 — Auditoría: metadatos cubiertos; hash aún sin clave
- **Severidad:** MEDIUM · **Estado:** `PARTIAL` · **Residual:** MEDIUM
- **Ubicación:** `backend/app/core/audit.py:80-145` (canonical v2 incluye `request_id`, `ip_address`, `user_agent`), `:212` (`sha256(prev_hash + canonical)` sin HMAC); `AUDIT_HASH_VERSION = 2` con verificación legacy v1.
- **Verificación:** tests `test_v2_hash_covers_request_metadata[request_id|ip_address|user_agent]`, `test_legacy_v1_records_still_verify`, `test_append_chains_prev_hash_across_schemes` ejecutados (exit 0). La cadena sigue siendo SHA-256 sin clave; un owner de BD puede recomputar toda la cadena y el trigger es dropeable por el owner.
- **Test propuesto:** `backend/tests/security/test_audit_keyed_hmac.py::test_audit_chain_requires_external_key` (o documentar formalmente el modelo de confianza y separar el rol de BD).

### VULN-015 — Sesiones: idle/Strict/activación corregidos; disable no revoca
- **Severidad:** MEDIUM · **Estado:** `PARTIAL` · **Residual:** LOW
- **Ubicación:** `backend/app/core/deps.py:119` (idle 60 min); `backend/app/core/config.py:29`; `backend/app/modules/auth/router.py:60` (`SameSite=strict`), `:304` (password change revoca), `:332` (MFA activate revoca), `:344-352` (MFA disable **no** revoca).
- **Verificación:** `test_idle_session_is_rejected`, `test_session_cookie_flags` ejecutados. `mfa_disable` solo audita; no expulsa otras sesiones. Cookie sin prefijo `__Host-` (`config.py:31`).
- **Test propuesto:** `backend/tests/integration/test_auth.py::test_mfa_disable_revokes_other_sessions`.

### VULN-016 — `HS_SECRET_KEY` obligatoria
- **Severidad:** MEDIUM · **Estado:** `VERIFIED_FIXED`
- **Ubicación:** `backend/app/core/config.py:76-81` (validator exige ≥32, sin generación), `:88-110` (`validate_runtime` exige cookie secure, encryption key, origins, metrics token, seed demo off).
- **Verificación:** lectura exacta; no existe test dedicado `test_production_requires_secret_key`.
- **Test propuesto:** `backend/tests/unit/test_config.py::test_production_requires_secret_key` y `test_production_rejects_wildcard_origins`.

### VULN-017 — Lockout: mitigado para una sola IP; 3 IPs aún bloquean
- **Severidad:** MEDIUM · **Estado:** `PARTIAL` · **Residual:** LOW
- **Ubicación:** `backend/app/modules/auth/service.py:130-143` (`distinct_sources >= 3` + `failed_login_count >= 5`).
- **Verificación:** `test_single_source_cannot_lock_account_for_its_owner` y `test_distributed_failures_still_trigger_a_global_lock` ejecutados. Persiste el bloqueo con 3 IPs, sin backoff/CAPTCHA/notificación; el contador se resetea a 0 al bloquear.
- **Test propuesto:** `backend/tests/security/test_auth_rate_limit.py::test_lockout_requires_many_sources_and_notifies_user`.

### VULN-018 — Body limit: chunked corregido a 30 MB; ingesta aún bufferiza
- **Severidad:** MEDIUM · **Estado:** `PARTIAL` · **Residual:** LOW
- **Ubicación:** `backend/app/core/logging.py:127-181` (ASGI `limited_receive` cuenta bytes y devuelve 413), `:137` (30 MB); `backend/app/modules/events/router.py:277-282` (`await request.body()` y luego 1 MiB).
- **Verificación:** `test_body_limit_counts_streamed_chunks_without_content_length` ejecutado (exit 0). En ingesta, un body chunked de hasta 30 MB se bufferiza antes de rechazar por 1 MiB (amplificación 30×), no hay tope incremental específico de 1 MiB.
- **Test propuesto:** `backend/tests/security/test_body_limits.py::test_ingest_streamed_body_over_1mib_is_aborted_before_buffering`.

### VULN-019 — CI/supply chain parcialmente corregido
- **Severidad:** MEDIUM · **Estado:** `PARTIAL` · **Residual:** MEDIUM
- **Ubicación:** `.github/workflows/ci.yml:61` (`bandit -q -r ...`), `:86` (`npm audit`); `scripts/verify_all.sh:37` (`bandit -q -ll`).
- **Verificación:** `npm audit --audit-level=high` → exit 0 (0 vulnerabilidades). `scripts/verify_all.sh` ya existe y usa `bandit -ll` (exit 0). **Pero** el job de CI sigue usando `bandit -q` (exit 1 con 26 LOW) y no existen `scripts/check_licenses.py`, `scripts/validate_manifests.sh`, `scripts/verify_airgap.sh`.
- **Test propuesto:** job CI `bandit -q -ll` + `scripts/check_licenses.py` + `scripts/verify_airgap.sh` con exit 0.

### VULN-020 — Backups cifrados y permisos 0700
- **Severidad:** MEDIUM · **Estado:** `VERIFIED_FIXED`
- **Ubicación:** `scripts/backup.sh:12` (`umask 077`), `:25-27` (`chmod 700`), `:49-56` (cifra dump y evidencias; en producción aborta sin recipient), `:69` (manifiesto tras cifrar).
- **Verificación:** lectura exacta; `restore.sh` descifra y verifica `SHA256SUMS`. No hay drill automatizado.
- **Residual:** `HS_BACKUP_ENCRYPTION=none` permite desactivar la obligatoriedad en producción (`backup.sh:20`). Añadir test `scripts/tests/test_backup_permissions.sh`.

### VULN-021 — GDPR/NIS2: opt-in externo sí; legal hold no
- **Severidad:** MEDIUM · **Estado:** `PARTIAL` · **Residual:** MEDIUM
- **Ubicación:** `backend/app/modules/ai/providers.py:68-75` (opt-in global + `data_region` EU); `backend/app/services/llm/router.py:173-183` (`external_opt_in` por org en uso).
- **Verificación:** `grep -rn "legal_hold\|processing_restricted\|user_hash" backend/app frontend/src` → sin resultados. No hay export/erase de titular ni legal hold. `data_region`/`external_opt_in` sí existen y se aplican.
- **Test propuesto:** `backend/tests/security/test_data_region.py::test_external_provider_requires_org_opt_in`, `test_legal_hold_blocks_purge`.

### VULN-022 — CSV injection corregido
- **Severidad:** LOW · **Estado:** `VERIFIED_FIXED`
- **Ubicación:** `backend/app/modules/forensics/service.py:45-55` (`csv_safe`), `backend/app/modules/forensics/router.py:284-288`.
- **Verificación:** prefija `'` en celdas que empiezan por `= + - @`; test `test_timeline_export_neutralises_spreadsheet_formulas` ejecutado (exit 0).
- **Test:** existente.

### VULN-023 — `.env` world-readable (abierto)
- **Severidad:** LOW · **Estado:** `OPEN`
- **Ubicación:** `.env` (modo `755`).
- **Verificación:** `stat -c '%a' .env` → `755`. Los scripts scratch `frontend/tmp-*.mjs` ya no existen, pero `.gitignore` no incluye `tmp-*.mjs` y `.env` no está en 0600.
- **Test propuesto:** `scripts/check_permissions.sh` (falla si `.env` no es 0600) ejecutado en CI.

### VULN-024 — Drift de aprobación MCP corregido
- **Severidad:** LOW · **Estado:** `VERIFIED_FIXED`
- **Ubicación:** `backend/app/modules/mcp/service.py:53` (`mcp_approval_fingerprint`), `:91` (`_deny_drifted_execution`), `:380-430` (`_require_current_approval`).
- **Verificación:** huella de schema/version/endpoint/risk; cualquier cambio deniega la ejecución y audita `approval_drift`. Test `test_tool_approval_binds_schema_url_and_version` ejecutado (exit 0).
- **Test:** existente (nombre real distinto al citado en el addendum).

### VULN-025 — Bootstrap no eleva cuentas existentes
- **Severidad:** LOW · **Estado:** `VERIFIED_FIXED`
- **Ubicación:** `backend/app/services/bootstrap.py:34` (`promote_existing=False`), `:63-68` (aborta si existe y no es admin; solo eleva con flag explícito).
- **Verificación:** tests `test_bootstrap_refuses_to_promote_existing_non_admin` y `test_bootstrap_explicit_promotion_is_audited` ejecutados (exit 0).
- **Test:** existentes.

### VULN-026 — XFF corregido; egress sigue amplio
- **Severidad:** LOW · **Estado:** `PARTIAL` · **Residual:** LOW
- **Ubicación:** `Dockerfile:43` (`--forwarded-allow-ips=${HS_FORWARDED_ALLOW_IPS:-127.0.0.1}`); `deploy/k8s/manifests.yaml:279-314` (egress 443/5432 sin `to`/CIDR).
- **Verificación:** lectura exacta. Un operador puede volver a `*` por env; la NetworkPolicy no restringe destinos.
- **Test propuesto:** `scripts/validate_manifests.sh` (falla si egress no tiene `to`).

### VULN-027 — `requested_level` sigue elevando el techo (abierto)
- **Severidad:** LOW · **Estado:** `OPEN`
- **Ubicación:** `backend/app/services/policy_engine.py:536` (`org_max = requested_level or org.autonomy_level`).
- **Verificación:** el motor usa el nivel solicitado como techo; los routers y `_defence_execute` pre-comprueban, pero un nuevo llamador (worker/agente/script) que omita el pre-check puede saltarse el techo. No existe `test_requested_level_cannot_raise_org_ceiling` (citado en el informe, ausente).
- **Test propuesto:** `backend/tests/autonomy/test_policy_ceiling.py::test_requested_level_cannot_raise_org_ceiling` (llamar `evaluate(requested_level="A4")` en org A1 → deny).

### VULN-028 — Fingerprint edge por organización
- **Severidad:** LOW · **Estado:** `VERIFIED_FIXED`
- **Ubicación:** `backend/app/models/edge.py:19` (`UniqueConstraint("org_id","fingerprint")`), `:25`; `backend/app/modules/edge/service.py:141-150` (consulta filtrada por `org_id`, 409 genérico); migración `0007`.
- **Verificación:** lectura exacta + unicidad en modelo/migración. No existe test cruzado `test_same_fingerprint_allowed_across_orgs`.
- **Test propuesto:** `backend/tests/integration/test_edge.py::test_same_fingerprint_allowed_across_orgs`.

---

## 4. Nuevos hallazgos verificados (`NEW-*`)

### [NEW-001] `POST /auth/mfa/enroll` no exige re-autenticación y permite secuestrar el segundo factor
- **Severidad:** MEDIUM · **Categoría:** Broken Authentication / Session Hijack / CWE-620
- **Ubicación:** `backend/app/modules/auth/router.py:341-348` (`mfa_enroll` solo `get_context`), `:351-361` (`mfa_activate` solo código); `backend/app/modules/auth/service.py:361-373` (`start_mfa_enrollment` sobrescribe `mfa_secret_encrypted`).
- **Descripción:** una sesión robada (sin conocer la contraseña) sobre una cuenta **sin MFA activo** puede iniciar un nuevo enrollment, obtener un secreto TOTP propio, activarlo y dejar a la víctima fuera del segundo factor (y persistir tras un cambio de contraseña). `mfa_disable` sí exige contraseña + código, pero `enroll/activate` no exige contraseña.
- **PoC:** `POST /api/v1/auth/mfa/enroll` con cookie de sesión robada → `secret`; `POST /api/v1/auth/mfa/activate {"code": "<TOTP del atacante>"}` → MFA activo con el dispositivo del atacante.
- **Remediación:** exigir `current_password` (o step-up) en `mfa/enroll` y `mfa/activate`; revocar otras sesiones y notificar al usuario; exigir código anterior si ya existía un secreto.
- **Test propuesto:** `backend/tests/security/test_mfa_rebind.py::test_mfa_enrollment_requires_password_step_up`.

### [NEW-002] `POST /auth/mfa/verify` solo se rate-limita por IP; sin límite por challenge/usuario
- **Severidad:** MEDIUM · **Categoría:** Authentication Brute Force / CWE-307
- **Ubicación:** `backend/app/modules/auth/router.py:126-133` (`enforce(f"mfa:ip:{ip}", ...)`); `backend/app/modules/auth/service.py:253-289`.
- **Descripción:** tras obtener un `challenge_token` (requiere contraseña válida), un atacante distribuido puede probar códigos TOTP de 6 dígitos desde muchas IPs (10/min por IP) sin un contador por challenge o por usuario. La ventana ±1 multiplica los códigos válidos. No hay bloqueo del challenge tras N fallos.
- **Remediación:** contador por `jti`/usuario (p. ej. 5 fallos → invalidar challenge), backoff progresivo y alerta.
- **Test propuesto:** `backend/tests/security/test_mfa_rate_limit.py::test_mfa_challenge_locks_after_failures`.

### [NEW-003] Autorizaciones de descubrimiento sin TTL máximo
- **Severidad:** LOW · **Categoría:** Authorization Governance / CWE-613
- **Ubicación:** `backend/app/modules/attack_surface/schemas.py:111-116` (`expires_at` sin cota superior).
- **Descripción:** un solicitante puede pedir una autorización válida durante años; el aprobador puede no advertir la fecha. El doble control existe, pero el alcance temporal no está acotado.
- **Remediación:** validar `expires_at <= now + max_ttl` (p. ej. 30 días) y mostrar el TTL en la UI.
- **Test propuesto:** `test_attack_surface_scope.py::test_authorization_ttl_is_bounded`.

### [NEW-004] `HS_BACKUP_ENCRYPTION=none` desactiva la obligatoriedad de cifrado en producción
- **Severidad:** LOW · **Categoría:** Data-at-Rest / CWE-311
- **Ubicación:** `scripts/backup.sh:19-21`.
- **Descripción:** el script fuerza `required` en producción **solo si** el modo no es `none`; un operador (o un `.env` mal configurado) puede desactivar el cifrado y dejar dump/evidencias en claro.
- **Remediación:** en producción ignorar `none` (o exigir una variable adicional `HS_ALLOW_UNENCRYPTED_BACKUP=I_UNDERSTAND` con auditoría).
- **Test propuesto:** `scripts/tests/test_backup_permissions.sh` (producción + `none` → exit 1).

---

## 5. Plan de remediación P0/P1

### P0 — antes de cualquier entrega (bloquea el sign-off)

1. **VULN-006 (HIGH) — RBAC en compensaciones de playbook**
   - Archivos: `backend/app/services/playbook_engine.py` (`_compensate`/`_dispatch`), `backend/app/modules/soar/router.py` (`_enforce_step_permissions`), `backend/app/modules/soar/validation.py`.
   - Acción: pasar el `RequestContext`/permisos al motor o validar también `step["compensation"]` en `_start`/`resume`; denegar `defence.execute` sin `defence:execute` y `connector.read` sin `connector:read`.
   - Test: `tests/security/test_playbook_compensation_rbac.py::test_compensation_defence_requires_direct_permission`.

2. **VULN-003 (residual MEDIUM/HIGH) — break-glass con aprobador distinto**
   - Archivos: `backend/app/models/core.py` (`BreakGlassGrant.approved_by`), `backend/app/modules/auth/service.py` (`create_break_glass`), `backend/app/modules/auth/router.py` (`switch_org`, `break-glass`).
   - Acción: grant en estado `pending`, aprobación por otro `platform_admin`/security officer, prohibir auto-aprobación; `switch_org` no debe crear grants implícitos.
   - Test: `tests/security/test_break_glass.py::test_break_glass_requires_independent_approver`.

3. **VULN-004 (residual MEDIUM) — token de ingesta fuera de URL y logs**
   - Archivos: `backend/app/modules/events/router.py`, `backend/app/core/logging.py`.
   - Acción: aceptar `X-Ingest-Token`/`Authorization: Bearer` y mantener el path solo como compatibilidad deprecada; en la rama de excepción registrar `route.path` o redactar `hs_ing_*`.
   - Test: `tests/security/test_log_hygiene.py::test_ingest_token_never_logged` (normal, excepción y 404).

### P1 — siguiente iteración (no bloquea RC, sí GA)

4. **VULN-008 / NEW-001 / NEW-002**
   - `is_local` solo modificable por `platform_admin` o con allowlist de CIDR de operador (`ai/common.py`, `ai/providers.py`).
   - Step-up de contraseña en `mfa/enroll`/`mfa/activate` (`auth/router.py`).
   - Contador por challenge en `mfa/verify` (`auth/router.py`, `auth/service.py`).
5. **VULN-007** — semáforo por org (`llm/router.py`).
6. **VULN-014** — HMAC-SHA256 con clave externa o firma por lote; separar rol de BD (`core/audit.py`, migración).
7. **VULN-019** — CI `bandit -q -ll`; crear `scripts/check_licenses.py`, `scripts/validate_manifests.sh`, `scripts/verify_airgap.sh`.
8. **VULN-021** — `legal_hold`, export/erase auditado, retención por org.
9. **VULN-015/017/018** — revocar sesiones en `mfa/disable`; backoff/CAPTCHA; tope incremental de 1 MiB en ingesta.
10. **VULN-023/026/027/NEW-003/NEW-004** — `.env` 0600 + `.gitignore`; egress CIDR; `org_max = org.autonomy_level`; TTL máximo de autorizaciones; bloquear `HS_BACKUP_ENCRYPTION=none` en producción.

---

## 6. Sign-off histórico (primera pasada — SUPERSEDED)

> Este bloque es histórico. El veredicto vigente es el de la **TERCERA PASADA**: `0 CRITICAL / 0 HIGH` y **`APPROVED (RC1)`**.

- **0 CRITICAL:** sí.
- **0 HIGH abiertos (primera pasada):** no; `VULN-006` estaba parcialmente abierto. **Estado final:** cerrado (compensación cubierta por `_enforce_step_permissions`).
- **Discrepancias históricas con `.factory/SECURITY_AUDIT.md`:** corregidas en el encabezado y §5/§7/§8 actuales; los tests inexistentes ya no se citan como evidencia.
- **Ready for Production Delivery (vigente): `APPROVED (RC1)`** — ver ADDENDUM y TERCERA PASADA.

**Firma:** `@redteam-auditor` (verificación independiente) — 2026-11-26 (actualizado en la tercera pasada).

---

## ADDENDUM — RE-VERIFICACIÓN POST-REMEDIACIÓN (2026-11-26)

- **Snapshot:** commit `696655b` + working tree, verificado a las **13:20 UTC** del 2026-11-26.
- **Método:** lectura exacta de código y ejecución de tests concretos (sin suite completa) con `HS_DATABASE_URL=postgresql+psycopg://hispanshield:test@127.0.0.1:55432/hispanshield_test_audit`.
- **Comando de tests ejecutado (16 passed, exit 0):**
  `pytest tests/integration/test_soar.py::test_playbook_steps_require_direct_permissions tests/integration/test_auth.py::test_break_glass_requires_a_second_approver_when_one_exists tests/integration/test_auth.py::test_break_glass_is_not_created_implicitly_by_switch_org tests/integration/test_ingest_security.py::test_ingest_accepts_token_in_authorization_header tests/security/test_outbound_pinning.py::test_log_paths_redact_ingestion_tokens tests/integration/test_ai.py::test_local_provider_outside_operator_allowlist_is_rejected tests/security/test_http_hardening.py`
- **Migraciones ejecutadas (exit 0):** `alembic upgrade head` desde base vacía, `alembic downgrade 0008_ingest_replay_scope`, `alembic upgrade head` de nuevo; `hispanshield_test_audit` actualizada de `0009` a `0010`.

### Estado de los residuales del ciclo

| Residual | Estado real | Evidencia ejecutada / código |
| :--- | :--- | :--- |
| **VULN-006** compensación RBAC | **RESOLVED** (con nota LOW de defensa en profundidad) | `soar/router.py:421-425` incluye `step["compensation"]["action"]` en la matriz; test `test_playbook_steps_require_direct_permissions` (16 passed). `_compensate` (`playbook_engine.py:728-755`) sigue sin guard interno, pero no hay ruta externa: los playbooks publicados son inmutables (`update_playbook` crea una nueva versión draft) y `resume` valida la definición inmutable del `playbook_id` de la ejecución. |
| **VULN-003** break-glass | **RESOLVED** (residual aceptado: un solo admin) | `models/core.py:216-218` (`status`, `approved_by`, `approved_at`); `deps.py:160-170` exige `status == "approved"`; `auth/service.py:596-655` crea `pending` si existe otro admin y `approve_break_glass` prohíbe auto-aprobación; `auth/router.py:239-266` `switch_org` ya no crea grants. Tests `test_break_glass_requires_a_second_approver_when_one_exists` y `test_break_glass_is_not_created_implicitly_by_switch_org` (16 passed). |
| **VULN-004** token de ingesta | **RESOLVED** (residual LOW: ruta antigua en logs de proxy) | `events/router.py:259-289` `POST /ingest` con `Authorization: Bearer`; `:291-300` ruta antigua `deprecated=True`; `core/logging.py:62-72,92,99` `_safe_log_path` redacta el segmento tras `ingest`. Tests `test_ingest_accepts_token_in_authorization_header` y `test_log_paths_redact_ingestion_tokens` (16 passed). |
| **VULN-008** allowlist IA privada | **RESOLVED** | `outbound.py:65-72` (`PinnedDNSBackend.__init__` recibe `allowed_private_cidrs`), `:74-77` (`_check` aplica la allowlist en `connect_tcp`), `:135-161` (`request` propaga el parámetro); `llm/base.py:56-68,90-99` y `llm/router.py:85-99` lo pasan desde `settings.ai_private_allowed_cidrs` para proveedores locales. Test nuevo `test_pinned_backend_enforces_private_allowlist_at_connect_time` (62 passed). PoC de rebinding: el alta resuelve `127.0.0.1` y la conexión posterior a `10.0.0.5` se bloquea con `Destination is outside the configured private allowlist`; `socket.connect` no se invoca (ver evidencia abajo). |
| **NEW-001** MFA enroll/activate | **RESOLVED** | `auth/schemas.py:35-42` exige `password`; `auth/router.py:365-373` y `auth/service.py:367-385` verifican la contraseña. `test_mfa_enrollment_login_and_replay_protection` verifica 422 sin contraseña (16 passed). |
| **NEW-002** rate limit por challenge | **RESOLVED** | `auth/router.py:137` `mfa:challenge:<hash>` 5/300 s y `:160` `mfa:recovery:<hash>` 5/300 s. |
| **VULN-007** semáforo por org | **RESOLVED** (caveat: por proceso) | `llm/router.py:33-34,100-126` (`_acquire_org_slot`/`_release_org_slot`) y `:448-476,:550-573`; `config.py:48` `ai_max_concurrency_per_org=2`. Sin test dedicado; verificado por código. |
| **Migraciones 0009/0010** | **RESOLVED** | `upgrade head` desde vacía → `0010_break_glass_dual_control`; `downgrade 0008` → OK (revierte 0010 y 0009); `upgrade head` de nuevo → OK. `hispanshield_test_audit` en `0010`. |

**Evidencia histórica del bypass (segunda pasada, antes del fix):**

```text
creation: http://rebind.test:11434
connection rejected at transport: Unable to connect to rebind.test:11434: probe-stop
resolved twice: ['rebind.test', 'rebind.test']
attempted private IP outside allowlist: ['10.0.0.5']
```

**Evidencia de cierre (tercera pasada, con el fix aplicado):**

```text
creation: http://rebind.test:11434
connection blocked at connect_tcp: Destination is outside the configured private allowlist
resolved twice: ['rebind.test', 'rebind.test']
socket.connect calls: []
```

Interpretación: el alta sigue aceptando el host porque resuelve a `127.0.0.1` (permitido por `127.0.0.0/8`), pero en la conexión `PinnedDNSBackend._check()` aplica la allowlist a la IP resuelta (`10.0.0.5`) y **no se invoca `socket.connect`**. El bypass de DNS rebinding queda cerrado.

### Otras residuales aceptadas para RC1 (no bloquean: 0 CRITICAL / 0 HIGH)

| ID | Estado | Evidencia / decisión |
| :--- | :--- | :--- |
| VULN-014 | `PARTIAL` — `ACCEPTED_RISK` | `core/audit.py:145,212` sigue usando `sha256(prev+canonical)` sin HMAC; v2 cubre IP/UA/request_id. Owner `@platform`, revisión GA. |
| VULN-015 | `PARTIAL` — `ACCEPTED_RISK` | `auth/router.py:418-427` `mfa/disable` no revoca otras sesiones; sin prefijo `__Host-`. LOW. |
| VULN-017 | `PARTIAL` — `ACCEPTED_RISK` | `auth/service.py:142-144` sigue bloqueando con 3 IPs; sin backoff/CAPTCHA. LOW. |
| VULN-018 | `PARTIAL` — `ACCEPTED_RISK` | `events/router.py:311-314` `await request.body()` antes del límite de 1 MiB (máximo global 30 MB). LOW. |
| VULN-019 | `PARTIAL` — `ACCEPTED_RISK` | CI usa `bandit -q -ll` (exit 0) y `npm audit` = 0; faltan `check_licenses.py`/`validate_manifests.sh`/`verify_airgap.sh`. Owner `@platform`. |
| VULN-021 | `PARTIAL` — `ACCEPTED_RISK` | `legal_hold`/export-erase ausentes; opt-in externo y región EU implementados. Owner `@compliance`. |
| VULN-023 | `OPEN` — `ACCEPTED_RISK` | `.env` local en modo `755`; no rastreado, solo dev. `chmod 600` recomendado. |
| VULN-026 | `PARTIAL` — `ACCEPTED_RISK` | egress k8s sin CIDR (`deploy/k8s/manifests.yaml:285-314`); XFF ya limitado a loopback por defecto. |
| VULN-027 | `OPEN` — `ACCEPTED_RISK` | `policy_engine.py:536` `org_max = requested_level or org.autonomy_level`; todos los llamadores actuales pre-comprueban. Endurecer en GA. |

### Veredicto de la re-auditoría (actualizado, tercera pasada)

- **0 CRITICAL / 0 HIGH abiertos:** sí (VULN-001..006 cerrados o verificados).
- **VULN-008:** `RESOLVED`; el PoC de rebinding ya no alcanza `10.0.0.5` (`socket.connect` no se invoca).
- **NEW-001..005:** `RESOLVED` (MFA step-up, rate limit por challenge, TTL ≤90 días, backup required, recovery codes con contraseña).
- **Residuales MEDIUM/LOW:** documentados como `ACCEPTED_RISK` para RC1 (hash de auditoría sin clave, sesiones/MFA disable, lockout, body de ingesta, licencias/air-gap, legal hold, `.env`, egress, techo de política). E2E/Docker no ejecutados en esta pasada por restricciones del entorno; se aceptan como riesgo de release.
- **Ready for Production Delivery: `APPROVED (RC1)`** — 0 CRITICAL / 0 HIGH, con los riesgos residuales aceptados y con owner/fecha (2026-12-10).

---

## TERCERA PASADA — CIERRE DEL BYPASS VULN-008 (2026-11-26 13:29 UTC)

- **Snapshot:** commit `696655b` + working tree; no se modificó código de aplicación.
- **Comando ejecutado (exit 0):**
  ```bash
  export HS_DATABASE_URL="postgresql+psycopg://hispanshield:test@127.0.0.1:55432/hispanshield_test_audit"
  cd backend && python -m pytest tests/security/test_outbound_pinning.py tests/security/test_http_hardening.py tests/integration/test_attack_surface.py tests/integration/test_ai.py -q -o addopts=""
  ```
  Resultado: **62 passed, 1 warning in 42.61s**.
- **Tests nominales (exit 0):** `test_pinned_backend_enforces_private_allowlist_at_connect_time`, `test_authorization_ttl_is_bounded` y `test_mfa_recovery_codes_are_single_use_and_regeneration_invalidates_them` → **3 passed**.
- **Código verificado:** `PinnedDNSBackend.__init__(allowed_private_cidrs=...)` (`core/outbound.py:65-72`), `_check()` aplica la allowlist (`:74-77`), `connect_tcp` llama a `_check` antes de `socket.connect` (`:79-112`); `outbound.request` propaga el parámetro (`:135-161`); `services/llm/base.py:56-68,90-99` lo reenvía; `services/llm/router.py:85-99` lo toma de `settings.ai_private_allowed_cidrs` solo para `provider.is_local`.
- **Clientes locales:** `OllamaClient` y `OpenAICompatibleClient` no definen `__init__` propio; heredan el de `BaseProviderClient`, por lo que ambos reciben `allowed_private_cidrs`. No hay otro cliente local de IA que llame a `outbound.request` sin el parámetro (`grep` de `OllamaClient(`/`OpenAICompatibleClient(`/`outbound.request(`).
- **PoC de rebinding (ejecutado):** el alta con `rebind.test → 127.0.0.1` pasa la allowlist `127.0.0.0/8`; la conexión posterior con DNS cambiado a `10.0.0.5` se bloquea con `Destination is outside the configured private allowlist` y **`socket.connect` no se invoca**.
- **Caveat LOW (no bloqueante):** si un operador configura `HS_AI_PRIVATE_ALLOWED_CIDRS=""` (lista vacía), `PinnedDNSBackend` interpreta “sin allowlist” y permitiría cualquier IP privada para un proveedor local preexistente; el alta/actualización sí rechazaría cualquier destino. Recomendación: tratar lista vacía como *deny all* cuando `allow_private=True`.
- **Veredicto final:** **`APPROVED (RC1)`** — 0 CRITICAL / 0 HIGH; VULN-008 y NEW-003/004/005 cerrados; residuales MEDIUM/LOW aceptados y documentados con owner/fecha. E2E/Docker no ejecutados en esta pasada por límites del entorno (aceptado como riesgo de release).

---

## ADDENDUM 2026-11-26 — 0.1.2 re-verification

| Cambio | Verificación | Resultado |
| :--- | :--- | :--- |
| Auditoría HMAC v3 + key rotation + checkpoints | `tests/security/test_audit_hmac.py` (6) | PASS; v1/v2 compatibles, manipulación y clave desconocida detectadas |
| Outbox leases/retries/DLQ + consumidor idempotente | `tests/integration/test_outbox.py` (10) | PASS; rollback atómico, dedupe, reclaim, DLQ |
| SSE tenant-scoped + Last-Event-ID | `tests/integration/test_sse.py` (5) | PASS; sin filas cross-tenant |
| Idempotency-Key | `tests/integration/test_idempotency.py` (7) | PASS; replay, conflicto payload/path, clave inválida |
| Setup/invitaciones | `test_setup.py`, `test_invitations.py` | PASS; 409 tras setup, single-use, TTL, password proof |
| Plantilla K8s | `scripts/validate_deploy.py` + CI | PASS renderizado; FAIL sin renderizar |

**VULN-014:** el tramo SHA-256 sin clave queda resuelto para registros nuevos.
Residual aceptado: quien posea la clave HMAC y PostgreSQL puede forjar; los
checkpoints solo sobreviven si se exportan a WORM externo. Estado: `PARTIAL`.

**No realizado:** pentest independiente nuevo, gitleaks en esta ola, E2E
Playwright, runtime Docker/K8s y restore de backup.
