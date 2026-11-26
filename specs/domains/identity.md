# DOMINIO: IDENTIDAD Y ACCESO

- **Código:** `IDN`
- **Ruta de implementación:** `backend/app/services/auth.py`, `backend/app/services/mfa.py`, `backend/app/core/{sessions,csrf,security}.py`, `backend/app/api/v1/auth.py`, `frontend/src/screens/{Login,Mfa,Setup}.tsx`
- **Estado:** `SPECIFIED`
- **ACs globales:** `AC-01..AC-08`

---

## 1. OBJETIVO

Proporcionar autenticación local fuerte (password + MFA), sesiones server-side seguras y trazables, y credenciales de servicio con privilegio mínimo, sin dependencia de IdP externo y sin introducir vectores de enumeración, fijación de sesión, CSRF ni escalada.

## 2. CONTEXTO

Los operadores acceden desde redes corporativas y, en ocasiones, desde ubicaciones de contingencia. El despliegue es air-gapped, por lo que no hay OIDC/SAML disponible. La superficie de identidad es la puerta de entrada a acciones potencialmente destructivas (`A3`/`A4`), de modo que la fortaleza de la autenticación condiciona la seguridad de toda la autonomía.

Decisiones asociadas: `ADR-009` (auth propio), `ADR-011` (cifrado de secretos MFA).

## 3. REQUISITOS FUNCIONALES

| ID | Requisito | Detalle verificable |
| :--- | :--- | :--- |
| `REQ-IDN-001` | Login con password | Verificación Argon2id (`time_cost=3`, `memory_cost=65536`, `parallelism=2`, `hash_len=32`). Respuesta genérica ante fallo. Éxito: cookie `hs_session` + `hs_csrf`, cuerpo `{user, organizations, active_organization_id}`. |
| `REQ-IDN-002` | Rotación de sesión | En login se invalida cualquier sesión previa del navegador; se genera nuevo token de 256 bits; en BD solo `sha256(token)`. |
| `REQ-IDN-003` | MFA TOTP | Secreto de 160 bits cifrado con Fernet; `otpauth://` con issuer `HISPANSHIELD`; ventana ±1 (30 s); anti-replay por último `counter` aceptado; 10 recovery codes hasheados. |
| `REQ-IDN-004` | Challenge de login | Si MFA activo: `202 {mfa_required:true, challenge_id}`; el challenge expira en 5 min, es de un solo uso y está ligado a IP + user-agent hash. |
| `REQ-IDN-005` | Política de contraseñas | Mínimo 12 caracteres, máximo 128, sin truncado; denylist local (10k contraseñas comunes + nombre del producto); rechazo si contiene el email; historial de 5 hashes. |
| `REQ-IDN-006` | Bloqueo progresivo | 5 fallos/15 min por `(email, ip)` → `429` con `Retry-After`; backoff exponencial hasta 1 h; contador en BD (no en memoria) para sobrevivir reinicios. |
| `REQ-IDN-007` | Sesiones | Idle timeout 30 min (configurable), absoluto 12 h; revocación inmediata por logout, cambio de password, cambio de rol o suspensión; listado de sesiones activas del usuario con IP/UA/último uso. |
| `REQ-IDN-008` | CSRF | Token de 32 bytes en cookie `hs_csrf` (no HttpOnly) + header `X-CSRF-Token`; comparación en tiempo constante; rotación tras login; exención solo para Bearer. |
| `REQ-IDN-009` | PAT | Formato `hs_pat_<public_id>_<secret>`; almacenamiento `sha256(secret)`; scopes (`assets:read`, `events:write`, `playbooks:execute`, `compliance:read`, …); expiración ≤365 días; último uso; revocación inmediata; nunca válido en `/auth/*`. |
| `REQ-IDN-010` | Auditoría | Todo evento (login ok/fail, MFA ok/fail, logout, revocación, cambio de password, creación/revocación de PAT) genera entrada con actor, IP, UA, `request_id`, resultado. |

## 4. REQUISITOS NO FUNCIONALES

| ID | Requisito |
| :--- | :--- |
| `NFR-IDN-01` | Verificación Argon2id ≤250 ms p95 en hardware de referencia (4 vCPU). |
| `NFR-IDN-02` | Login completo (sin MFA) ≤400 ms p95, incluida escritura de sesión y auditoría. |
| `NFR-IDN-03` | Ningún endpoint de auth revela existencia de email (mismo código, mensaje y timing aproximado). |
| `NFR-IDN-04` | Los secretos (password, TOTP, recovery codes, tokens) nunca aparecen en logs ni en respuestas. |
| `NFR-IDN-05` | Rate limiting distribuido por BD para coherencia entre workers. |

## 5. DEPENDENCIAS

| Dependencia | Tipo | Nota |
| :--- | :--- | :--- |
| `core/security.py` (Argon2id, HMAC, UUIDv7) | Interna | TASK-006 |
| `core/audit.py` (cadena de hash) | Interna | TASK-007 |
| `organizations` (memberships para resolver orgs del usuario) | Dominio | TASK-019/020 |
| `cryptography` (Fernet) | Externa | Cifrado de secreto TOTP |
| `pyotp` | Externa | TOTP RFC 6238 |

## 6. CONTRATOS

| Método | Endpoint | Entrada | Salida | Errores |
| :--- | :--- | :--- | :--- | :--- |
| POST | `/api/v1/auth/login` | `{email, password, remember?}` | `200 {user, organizations, csrf_token}` + cookies; o `202 {mfa_required, challenge_id}` | `400, 401, 429` |
| POST | `/api/v1/auth/mfa/verify` | `{challenge_id, code}` o `{challenge_id, recovery_code}` | `200 {user, organizations}` + cookies | `400, 401, 410` |
| POST | `/api/v1/auth/mfa/enroll` | `{}` | `200 {otpauth_url, secret_once}` | `401, 409` (ya activo) |
| POST | `/api/v1/auth/mfa/activate` | `{code}` | `200 {recovery_codes[]}` | `400, 401, 409` |
| POST | `/api/v1/auth/logout` | — | `204` | `401` |
| GET | `/api/v1/auth/me` | — | `200 {user, memberships, permissions, active_organization_id}` | `401` |
| POST | `/api/v1/auth/password/change` | `{current_password, new_password}` | `204` (revoca otras sesiones) | `400, 401, 422` |
| GET | `/api/v1/auth/sessions` | — | `200 [{id, ip, user_agent, last_used_at, current}]` | `401` |
| DELETE | `/api/v1/auth/sessions/{id}` | — | `204` | `401, 404` |
| GET/POST/DELETE | `/api/v1/users/{id}/tokens` | `{name, scopes[], expires_at}` | `201 {token_once}` / `204` | `403, 422` |

**Cookie de sesión:** `hs_session=<opaque>; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=43200`.
**Cookie CSRF:** `hs_csrf=<token>; Secure; SameSite=Strict; Path=/`.
**Error de login:** `{"error":{"code":"invalid_credentials","message":"Credenciales inválidas","request_id":"..."}}` siempre, sin distinguir usuario inexistente, password errónea o usuario deshabilitado.

## 7. CASOS DE USO

1. **Primer acceso:** el operador recibe credenciales del `owner`; inicia sesión; es forzado a cambiar password y a enrolar MFA si su rol lo exige; se registran ambos eventos.
2. **Turno de SOC:** login + TOTP; selección de organización; sesión idle 30 min; al expirar, la UI conserva la ruta y redirige a `/login?next=...`.
3. **Automatización:** el integrador crea un PAT con `events:write` y `assets:read`; el token no puede leer incidentes ni ejecutar playbooks.
4. **Incidente de credencial:** el `admin` sospecha compromiso; revoca todas las sesiones del usuario y rota su MFA; la acción queda auditada y el usuario recibe `401` en su siguiente petición.
5. **Auditoría:** el auditor verifica que cada login fallido de la última semana está en la cadena con IP y resultado.

## 8. CASOS BORDE

| Escenario | Comportamiento esperado |
| :--- | :--- |
| Usuario inexistente | `401 invalid_credentials` (mismo timing objetivo), contador de rate limit incrementado |
| Usuario deshabilitado | `401 invalid_credentials`; auditoría registra `reason=disabled` internamente |
| MFA con código expirado | `401 invalid_mfa_code`, sin consumir el challenge si quedan intentos (máx 5) |
| Challenge reutilizado | `410 challenge_consumed` |
| Recovery code reutilizado | `401 invalid_recovery_code`; el código se marca usado en la misma transacción |
| Cookie con token revocado | `401 session_invalid`; se borra la cookie en la respuesta |
| Reloj desincronizado >90 s | TOTP falla; mensaje sugiere verificar NTP (sin revelar detalles internos) |
| Cambio de password con sesiones activas | Se revocan todas salvo la actual; se notifica por email si está configurado SMTP |
| PAT usado en `/auth/login` | `401 bearer_not_allowed_on_auth` |
| Fuerza bruta distribuida | Rate limit por email agrega entre IPs; bloqueo progresivo; alerta de seguridad `auth_bruteforce` |
| Cookie ausente en mutación Bearer | Permitido (no requiere CSRF); se registra `auth_method=pat` |

## 9. AMENAZAS ESPECÍFICAS

| Amenaza | Vector | Control |
| :--- | :--- | :--- |
| Credential stuffing | Listas filtradas | Argon2id, rate limit, MFA para privilegiados, denylist |
| Session fixation | Cookie preexistente | Rotación en login, token nuevo, `SameSite=Strict` |
| CSRF | Formulario cross-site | Double-submit + `SameSite=Strict` + verificación de Origin |
| Enumeración de usuarios | Mensajes/timing distintos | Respuesta uniforme, hash dummy para emails inexistentes |
| Robo de PAT | Logs o repositorio | Solo hash en BD, prefijo visible, scope mínimo, expiración |
| Bypass de MFA | Reutilización de challenge | Challenge de un solo uso, TTL 5 min, ligado a IP/UA |
| Fuerza bruta de TOTP | 6 dígitos | 5 intentos por challenge, rate limit, bloqueo |
| Elevación por cambio de rol | Sesión antigua con permisos cacheados | Revocación y reemisión al cambiar rol |

## 10. CRITERIOS DE ACEPTACIÓN

| AC | Criterio | Test |
| :--- | :--- | :--- |
| `AC-01` | Login válido → `200` + cookie rotada con flags correctos | `backend/tests/integration/test_auth_login.py::test_login_sets_rotated_session_cookie` |
| `AC-02` | MFA activo → `202` y sesión solo tras código válido | `backend/tests/integration/test_auth_mfa.py::test_totp_challenge_required_and_verified` |
| `AC-03` | 5 fallos → `429` sin enumeración | `backend/tests/security/test_auth_rate_limit.py::test_lockout_and_no_user_enumeration` |
| `AC-04` | Mutación sin CSRF válido → `403` | `backend/tests/security/test_csrf.py::test_double_submit_enforced` |
| `AC-05` | PAT con scope aplica solo lo permitido | `backend/tests/integration/test_api_tokens.py::test_scoped_bearer_token` |
| `AC-06` | Revocación y expiración idle/absoluta | `backend/tests/integration/test_session_lifecycle.py::test_revocation_and_idle_expiry` |
| `AC-07` | Password débil → `422` con campo | `backend/tests/unit/test_password_policy.py` |
| `AC-08` | Eventos de auth en cadena de auditoría | `backend/tests/integration/test_audit_chain.py::test_auth_events_chained` |

## 11. ESTRATEGIA DE TEST

- **Unit:** política de contraseñas, formato/parseo de PAT, TOTP (ventana, replay), hash/verify.
- **Integración:** login, MFA, sesiones, revocación, CSRF, tokens, con PostgreSQL real.
- **Seguridad:** enumeración (comparación de respuestas y tiempos con tolerancia), fijación de sesión, fuerza bruta, flags de cookie, fugas en logs.
- **E2E:** `/login` → `/mfa` → shell; sesión expirada → redirección con `next`; logout.
- **Carga:** 200 logins concurrentes sin degradar p95 >400 ms.

## 12. EVIDENCIA REQUERIDA

1. Salida de `pytest -q backend/tests/{unit,integration,security} -k "auth or session or token or csrf"`.
2. Cabeceras `Set-Cookie` capturadas en test mostrando `HttpOnly; Secure; SameSite=Strict`.
3. Entrada de auditoría de ejemplo (JSON) con `prev_hash`/`entry_hash` verificados.
4. Resultado de `frontend/e2e/auth.spec.ts`.
5. Captura del `429` con `Retry-After` en el intento 6.
