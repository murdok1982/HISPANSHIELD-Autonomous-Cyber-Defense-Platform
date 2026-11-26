# ADVERSARIAL SECURITY AUDIT REPORT

- **Audit Status:** `FAIL (OPEN FINDINGS)` — *estado inicial: auditoría adversarial no ejecutada; PASS queda prohibido hasta completar TASK-150*
- **Auditor Agent:** `@redteam-auditor`
- **Target Commit / Iteration:** `pre-commit / iteración 0 (fase de especificación)`
- **Scope:** `backend/`, `edge/`, `frontend/`, `deploy/`, `infra/`, `scripts/`, configuración y cadena de suministro
- **Summary Counts:**
  - `CRITICAL`: 0 registrados (auditoría pendiente)
  - `HIGH`: 0 registrados (auditoría pendiente)
  - `MEDIUM`: 0 registrados (auditoría pendiente)
  - `LOW`: 0 registrados (auditoría pendiente)

> **EXIT GATE RULE:** El proyecto NO puede darse por finalizado mientras exista cualquier hallazgo `CRITICAL` o `HIGH` en estado `OPEN`.
> **Regla adicional HISPANSHIELD:** cualquier hallazgo que permita (a) cruzar `organization_id`, (b) ejecutar una acción autónoma sin decisión `allow` de política, (c) saltarse un kill switch, o (d) leer un secreto de conector en claro, se clasifica como `CRITICAL` aunque su exploit requiera autenticación.

---

## 1. ATTACK SURFACE & THREAT MODEL

### 1.1 External Entry Points

| # | Superficie | Detalle | Autenticación | Notas de riesgo |
| :--- | :--- | :--- | :--- | :--- |
| `EP-01` | `/api/v1/auth/*` | login, MFA verify, logout, password change, enroll | Público (rate-limited) / sesión | Enumeración de usuarios, credential stuffing, bypass de MFA |
| `EP-02` | `/api/v1/setup` | bootstrap inicial | Público solo si `organizations.count == 0` | Carrera de bootstrap, creación de owner no autorizado |
| `EP-03` | API REST autenticada `/api/v1/**` | ~70 rutas de dominio | Cookie `hs_session` + CSRF o Bearer PAT | IDOR, escalada de rol, mass assignment |
| `EP-04` | `/api/v1/events/webhook/{connector_id}` | ingesta push | HMAC-SHA256 | Replay, firma débil, payload bomber, SSRF indirecto |
| `EP-05` | Syslog UDP/TCP `:5514` | RFC 5424/3164 | Red permitida (allowlist) | Spoofing de origen, inundación, parsing malicioso |
| `EP-06` | `/api/v1/events/stream` (SSE) | stream en vivo | Sesión | Fuga cross-org en filtros, agotamiento de conexiones |
| `EP-07` | Uploads (`/assets/import`, `/evidence`, `/ai/documents`, `/compliance/evidence`) | CSV/JSON/PDF/`.nessus` | Rol + CSRF | RCE por parser, path traversal, zip bomb, MIME spoofing |
| `EP-08` | `/api/v1/mcp/tools/{name}/invoke` | tool broker | Rol + política de agente | Confused deputy, SSRF vía tool, ejecución no autorizada |
| `EP-09` | `/api/v1/ai/*` | chat/RAG/embeddings | Rol + presupuesto | Prompt injection, exfiltración de contexto, coste |
| `EP-10` | `/api/v1/autonomy/*` | evaluate/actions/kill-switches | Rol + política | Acción destructiva no autorizada, bypass de aprobación |
| `EP-11` | Edge → Core (`/api/v1/edge/ingest`) | push mTLS | mTLS + HMAC | Suplantación de gateway, replay, orden manipulado |
| `EP-12` | `/metrics`, `/healthz`, `/readyz` | observabilidad | Red interna / token opcional | Divulgación de topología y versiones |
| `EP-13` | Frontend estático | SPA | — | XSS almacenado vía nombres/evidencias, clickjacking |
| `EP-14` | Dependencias y cadena de suministro | PyPI/npm | — | Paquete comprometido, licencia incompatible, CVE |

### 1.2 Authentication Mechanism

- Sesión de servidor con cookie `hs_session` `HttpOnly; Secure; SameSite=Strict; Path=/`; token aleatorio de 256 bits; en BD solo `sha256(token)`; rotación en login y cambio de privilegio; idle 30 min / absoluto 12 h.
- CSRF double-submit: cookie `hs_csrf` (legible por JS) + header `X-CSRF-Token`, comparación `hmac.compare_digest`, obligatorio en métodos mutantes autenticados por cookie.
- Bearer PAT `hs_pat_<id>_<secret>` con scopes, expiración y revocación; **nunca** válido en `/auth/*`.
- Password Argon2id (`time_cost=3`, `memory_cost=65536`, `parallelism=2`); TOTP RFC 6238 con ventana ±1; recovery codes hasheados de un solo uso.
- RBAC por organización (`owner/admin/responder/analyst/viewer/auditor`) + `platform_admin` con `break-glass` auditado y TTL ≤60 min.

### 1.3 Sensitive Data Assets

| Activo | Clasificación | Protección |
| :--- | :--- | :--- |
| `users.password_hash` | Confidencial | Argon2id, nunca serializado, nunca en logs |
| `users.mfa_secret_enc`, `recovery_codes` | Secreto | Fernet (AES-128-CBC+HMAC) con clave externa |
| `connector_secrets.value_enc` | Secreto | Fernet, `has_secret` en API, jamás en claro en logs/respuestas |
| `api_tokens.token_hash` | Secreto | SHA-256 del secreto; prefijo para identificación |
| Evidencias forenses | Confidencial / legal hold | Hash SHA-256, almacenamiento fuera de webroot, permisos 0600, acceso auditado |
| Eventos SIEM (IPs, usuarios, correos) | PII potencial | Minimización, retención configurable, redacción en logs |
| `audit_log` | Integridad crítica | Cadena de hash append-only, trigger anti-tamper |
| Decisiones de autonomía | Integridad crítica | `decision_id`, `policy_version`, reglas aplicadas, firma en cadena |
| SBOM y artefactos de release | Integridad | Checksums, firma opcional (cosign), almacenamiento en `reports/release/` |

### 1.4 Trust Boundaries

```text
[Navegador] --TLS--> [Reverse proxy] --HTTP loopback--> [API FastAPI]
                                                          |
                                    +---------------------+---------------------+
                                    |                                           |
                              [PostgreSQL]                              [Workers]
                                    |                                           |
                              [Volumen evidencias]                    [Conectores externos]
                                                                            |
                                                                    [Edge gateways] --mTLS--> [API]
[LLM local (Ollama/vLLM)] <--HTTP loopback-- [AI gateway] --opt-in--> [Proveedor externo]
```

Fronteras donde se aplica validación estricta: (1) navegador→proxy, (2) proxy→API, (3) API→BD (consultas parametrizadas), (4) API→servicios externos (allowlist anti-SSRF), (5) edge→API (mTLS+HMAC), (6) LLM→broker (el LLM **nunca** es autoridad de autorización).

### 1.5 STRIDE (matriz de amenazas)

| Frontera | S | T | R | I | D | E |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| Navegador→API | CSRF, session fixation | Modificación de payload (mitigado por validación server-side) | Repudio de acción destructiva (mitigado por auditoría + confirmación) | XSS en nombres/evidencias | Rate limit | Escalada vía `platform_admin` |
| API→BD | — | SQLi (parametrizado) | — | Fuga cross-org (404 uniforme) | Query amplia (guard) | Rol de BD excesivo (revisar grants) |
| API→Externos | — | SSRF/metadata | — | Exfiltración de secretos | Timeouts | Conector malicioso (allowlist) |
| Edge→Core | Suplantación (mTLS) | Replay (nonce+secuencia) | — | — | Flood (límites) | Gateway comprometido (cuarentena por org) |
| LLM→Broker | Prompt injection | Parámetros de acción manipulados | — | Fuga de contexto en prompt | Coste | Tool no allowlisted |
| Insider | — | Manipulación de política | Negación de acción | Lectura de evidencias | — | `break-glass` sin justificación |

---

## 2. MANDATORY APPSEC VERIFICATION CHECKLIST

> Cada casilla se marca solo con evidencia ejecutada (comando + salida). Las casillas sin marcar bloquean el PASS.

### 2.1 Injection & Input Validation
- [ ] Todas las entradas externas (body, query, params, headers, multipart, syslog, webhooks, STIX, CSV) pasan por validación estricta de esquema (Pydantic v2 `extra="forbid"` / JSON Schema) en la frontera.
- [ ] Consultas a base de datos 100% parametrizadas (sin concatenación de strings en SQL); `text()` solo con bind params y revisión explícita.
- [ ] Sin uso inseguro de `dangerouslySetInnerHTML`, `eval()`, `new Function()`, `pickle`, `yaml.load` sin `SafeLoader`, ni `subprocess` con `shell=True` e input de usuario.
- [ ] El DSL de detección no se traduce a SQL concatenado: se compila a AST con campos/operadores allowlisted.
- [ ] Los parsers de ficheros (Nessus XML, STIX JSON, CSV, PDF de evidencias) tienen límites de tamaño, profundidad y número de entidades; entidades XML externas deshabilitadas (XXE).
- [ ] La salida de IA nunca se interpreta como HTML/SQL/comando; se muestra como texto y se sanea en informes.
- [ ] Paths de ficheros derivados de input se resuelven y se verifica que permanecen dentro del directorio permitido (anti path traversal).

### 2.2 Authentication, Sessions & Access Control
- [ ] Contraseñas almacenadas con Argon2id (nunca MD5/SHA1/SHA256 plano); parámetros verificados en test.
- [ ] Verificación de autorización (ownership/RBAC/tenancy) ejecutada en el servidor en **cada** endpoint y Server Action (prevención de IDOR).
- [ ] Toda consulta de recurso incluye `organization_id` en el `WHERE`; cross-org devuelve `404` uniforme (sin filtrar existencia).
- [ ] Cookies de sesión configuradas con `HttpOnly`, `Secure` y `SameSite=Strict`; rotación en login y cambio de privilegio.
- [ ] CSRF double-submit activo en todas las mutaciones autenticadas por cookie; exención solo para Bearer.
- [ ] Rate limiting activo en login, MFA, setup, recuperación, webhooks, ingesta, IA y mutaciones críticas.
- [ ] TOTP verificado con ventana acotada y protección anti-replay; recovery codes de un solo uso y hasheados.
- [ ] `platform_admin` no accede a datos de dominio sin `break-glass` con justificación, TTL y auditoría.
- [ ] Separación de funciones: quien solicita una acción A2/A3/A4 no puede ser el único aprobador.

### 2.3 Secrets, Configuration & HTTP Hardening
- [ ] Cero secretos, API keys o credenciales hardcodeadas en el código fuente o historial Git (`.env` en `.gitignore` y `.env.example` creado).
- [ ] `HISPANSHIELD_SECRET_KEY` obligatoria en producción; el arranque falla si falta o es débil; nunca se loguea.
- [ ] Secretos de conectores y MFA cifrados en reposo (Fernet); la API solo expone `has_secret`/`prefix`.
- [ ] CORS configurado con orígenes explícitos (prohibido `Access-Control-Allow-Origin: *` en APIs autenticadas).
- [ ] Cabeceras de seguridad configuradas: `Content-Security-Policy` (sin `unsafe-eval`, `frame-ancestors 'none'`), `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`.
- [ ] Los mensajes de error en producción ocultan stack traces, rutas internas y versiones de servidor; incluyen `request_id`.
- [ ] Logs con redacción verificada de `password`, `token`, `authorization`, `cookie`, `secret` y patrones de API key.
- [ ] Contenedores/procesos no-root, capabilities mínimas, `no-new-privileges`, rootfs read-only donde sea posible.

### 2.4 SSRF, File Handling & Dependencies
- [ ] Si existen descargas de URLs externas o webhooks, se bloquean rangos IP privados (`127.0.0.1`, `169.254.169.254`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `::1`, `fc00::/7`) y se revalida la IP resuelta tras conectar (anti DNS-rebinding).
- [ ] Si hay subida de archivos, se valida MIME real (magic bytes), tamaño máximo (50 MB evidencias / 10 MB import), nombres sanitizados (UUID) fuera del webroot ejecutable y permisos `0600`.
- [ ] Auditoría de dependencias ejecutada sin CVEs críticos/altos explotables (`pip-audit`, `npm audit --audit-level=high`).
- [ ] SBOM CycloneDX generado y allowlist de licencias verificada (sin AGPL/SSPL/BSL en runtime).
- [ ] TLS verificado en todas las llamadas salientes (`verify=True`); prohibido `verify=False` e `InsecureSkipVerify`.

### 2.5 Autonomy, AI & Agent-Specific Controls (HISPANSHIELD)
- [ ] El motor de política es la **única** autoridad de ejecución; el LLM no puede aprobar ni ejecutar acciones.
- [ ] Deny-by-default verificado: sin política aplicable → `deny` con `decision_id` persistido.
- [ ] Blast radius, presupuesto por hora, freeze windows y niveles A0..A4 aplicados **antes** de invocar el conector.
- [ ] Kill switch (global/org/conector/activo) efectivo ≤5 s y evaluado antes de cada paso del broker.
- [ ] Toda acción tiene verificación post-acción y rollback idempotente declarados; fallo de verificación → `rolled_back`.
- [ ] Tool-calls MCP limitadas por allowlist y validadas contra JSON Schema; inputs inválidos no alcanzan el servidor MCP.
- [ ] Defensas anti prompt-injection: contenido no confiable delimitado, instrucciones de sistema inmutables, detección de override, 0 bypass en corpus.
- [ ] Presupuesto de IA aplicado por organización; sin proveedor → `503 ai_unavailable` (nunca datos fabricados).

### 2.6 Logging, Auditability & Incident Readiness
- [ ] Cadena de auditoría append-only verificable; alteración detectada con `seq` inconsistente.
- [ ] Eventos de autenticación, autorización denegada, acciones autónomas, accesos a evidencias y cambios de política auditados.
- [ ] Sin PII innecesaria en eventos SIEM; retención configurable y `legal_hold` prevalente.
- [ ] Procedimiento de respuesta a incidentes de seguridad del producto documentado (`SECURITY.md` + `docs/incident-response-manual.md`).
- [ ] Backup cifrado y restore probado; secretos incluidos en el procedimiento de recuperación.

---

## 3. VULNERABILITY FINDINGS LOG

> Registrar aquí cada hallazgo detectado. Por cada `CRITICAL` o `HIGH`, añadir inmediatamente una tarea `SEC-FIX-XXX` en `.factory/TASKS.md` y una fila en la cola de remediación.

**Formato obligatorio por hallazgo**

### [VULN-XXX] Título descriptivo
- **Severity:** `CRITICAL` | `HIGH` | `MEDIUM` | `LOW`
- **CVSS 3.1:** `X.X (vector)`
- **Category:** p.ej. Broken Access Control (IDOR) / SQL Injection / XSS / Hardcoded Secret / SSRF / Prompt Injection / Autonomy Bypass
- **Location:** `ruta/al/archivo.py:L42`
- **Status:** `OPEN` | `FIXED` | `VERIFIED` | `ACCEPTED_RISK` (solo LOW/MEDIUM con justificación y caducidad)
- **Exploit Scenario (PoC):** petición/payload exacto y precondiciones (rol, organización, configuración).
- **Impact:** qué dato o capacidad se compromete y en qué tenants.
- **Required Remediation:** cambio exacto de código/configuración.
- **Regression Test:** ruta del test añadido que falla antes y pasa después.
- **Verification Proof:** comando ejecutado y salida (exit 0), más revisión de `@qa-verifier`.

**Estado actual:** sin hallazgos registrados porque la auditoría no se ha ejecutado. Este documento **no** puede declararse `PASS` con la checklist vacía.

### 3.1 Registro

| ID | Severity | Category | Location | Status | Tarea |
| :--- | :--- | :--- | :--- | :--- | :--- |
| — | — | — | — | — | — |

### 3.2 Riesgos pre-identificados a verificar obligatoriamente (hipótesis de auditoría)

| ID | Hipótesis de fallo | Vector | Verificación esperada |
| :--- | :--- | :--- | :--- |
| `H-01` | Fuga cross-org en un listado por filtro no scoped (p.ej. búsqueda de eventos o export STIX) | `GET` con `X-Organization-Id` propio y filtro que alcanza IDs ajenos | `test_tenant_isolation.py` cubre todos los recursos |
| `H-02` | IDOR en evidencias por descarga directa con UUID ajeno | `GET /evidence/{id}/download` | 404 uniforme + auditoría de intento |
| `H-03` | Bypass de aprobación en playbook ejecutando nodo posterior por carrera | dos ejecuciones concurrentes sobre el mismo `execution_id` | test de concurrencia + lock por ejecución |
| `H-04` | Acción autónoma ejecutada con decisión `require_approval` sin aprobación por defecto optimista | payload manipulado en broker | test de política + broker sin ruta alternativa |
| `H-05` | Kill switch no evaluado en pasos intermedios (solo al encolar) | activar halt durante ejecución de playbook largo | halt ≤5 s por paso |
| `H-06` | Prompt injection que induce tool-call destructiva vía contenido de documento RAG | documento con instrucciones | corpus `examples/prompt-injection/` |
| `H-07` | Secreto de conector devuelto en `PATCH` o en export de configuración | respuesta de API | test de serialización + grep de `value_enc` |
| `H-08` | SSRF en "test connection" de conector apuntando a metadata cloud | `POST /connectors/{id}/test` con host interno | guard anti-SSRF + test |
| `H-09` | Replay de webhook con firma capturada | reenvío de payload firmado | idempotencia + ventana temporal + nonce |
| `H-10` | Path traversal en import de evidencias con nombre manipulado | multipart filename `../../etc/passwd` | nombres UUID + validación de ruta |
| `H-11` | Inyección en DSL de detección hacia SQL/expresión | regla con operador malicioso | parser allowlist + test |
| `H-12` | Escalada de `admin` a `owner` vía cambio de rol no restringido | `PATCH /members/{id}` | matriz RBAC + guard de último owner |

---

## 4. AUTOMATED SECURITY TOOLING LOG

> Ejecutar en cada gate (`scripts/verify_all.sh`). Un exit code distinto de `0` bloquea el avance.

| Tool / Command | Scope | Exit Code | Findings Summary |
| :--- | :--- | :--- | :--- |
| `ruff check backend edge` | Código Python (lint + reglas de seguridad seleccionadas) | `PENDING` | No ejecutado |
| `mypy --strict backend/app` | Tipos | `PENDING` | No ejecutado |
| `bandit -r backend edge -ll` | Código Python (SAST) | `PENDING` | No ejecutado |
| `pip-audit -r backend/requirements.txt` (o `uv pip audit`) | Dependencias Python | `PENDING` | No ejecutado |
| `npm audit --audit-level=high` | Dependencias frontend | `PENDING` | No ejecutado |
| `gitleaks detect --no-banner --redact` | Todo el repo + historial | `PENDING` | No ejecutado |
| `semgrep --config p/owasp-top-ten` (opcional, si disponible) | Código backend/frontend | `PENDING` | No ejecutado |
| `scripts/generate_sbom.sh` + `scripts/check_licenses.py` | Cadena de suministro | `PENDING` | No ejecutado |
| `pytest -q backend/tests/security backend/tests/autonomy` | Pruebas de seguridad y autonomía | `PENDING` | No ejecutado |
| `npm run test:e2e -- e2e/a11y.spec.ts` | Accesibilidad (WCAG AA) | `PENDING` | No ejecutado |
| `scripts/validate_manifests.sh` | Compose/k8s/proxy | `PENDING` | No ejecutado |
| `bash scripts/verify_airgap.sh` | Instalación sin red | `PENDING` | No ejecutado |

**Criterio de bloqueo:** cualquier `CRITICAL`/`HIGH` en pip-audit/npm audit, cualquier hallazgo `HIGH` de bandit, cualquier secreto detectado por gitleaks, o cualquier test de `tests/security`/`tests/autonomy` en rojo impide el PASS.

---

## 5. FINAL RELEASE SIGN-OFF

- **All `CRITICAL` findings resolved & verified:** `NO` (auditoría pendiente)
- **All `HIGH` findings resolved & verified:** `NO` (auditoría pendiente)
- **`MEDIUM`/`LOW` residuals documented with owner and due date:** `NO`
- **SBOM + license allowlist verified:** `NO`
- **Air-gap install verified:** `NO`
- **Multi-tenant isolation suite green:** `NO`
- **Autonomy lab (deny-by-default, kill switch, rollback) green:** `NO`
- **Prompt-injection corpus green:** `NO`
- **Ready for Production Delivery:** `BLOCKED`

**Condiciones exactas para cambiar a `APPROVED`:**
1. `TASK-150` ejecutada y checklist §2 completa con evidencia.
2. `0 CRITICAL` y `0 HIGH` en estado `OPEN` (todos `VERIFIED` con test de regresión).
3. `scripts/verify_all.sh` exit `0` (backend, frontend, e2e, dependencias, SBOM, aislamiento, autonomía, prompt-injection).
4. `reports/acceptance-matrix.md` con cada `AC-XX` de `SPEC.md §3` mapeado a test y resultado.
5. Firma del `@redteam-auditor` y del `@qa-verifier` en este documento con fecha y commit.
