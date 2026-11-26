# MODELO DE AUTORIZACIÓN

- **Documento:** `specs/security/authorization-model.md`
- **Estado:** `APPROVED` v1.0 — **normativo**: si el código difiere de esta matriz, el código es el defecto
- **Implementación:** `backend/app/core/permissions.py`, `backend/app/core/tenancy.py`, `backend/app/api/deps.py`

---

## 1. PRINCIPIOS

1. **Deny-by-default.** Sin permiso explícito, la petición se deniega.
2. **Servidor es autoridad.** La UI oculta, pero el servidor decide.
3. **Dos ejes:** pertenencia (¿es miembro de la org?) y capacidad (¿su rol permite la acción?).
4. **Scope explícito:** cada endpoint declara `required_permission` y `scope ∈ {org, global, self}`.
5. **Uniformes:** recurso inexistente y recurso de otra org producen la misma respuesta (`404`).
6. **Separación de funciones** en acciones de alto impacto (aprobar ≠ solicitar).

---

## 2. ROLES Y PERMISOS BASE

| Permiso | `viewer` | `analyst` | `responder` | `admin` | `owner` | `auditor` | `platform_admin` |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `org.read` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ (break-glass) |
| `org.settings.write` | — | — | — | ✅ | ✅ | — | — |
| `org.delete` | — | — | — | — | ✅ | — | — |
| `member.read` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| `member.invite` | — | — | — | ✅ | ✅ | — | — |
| `member.role.write` | — | — | — | ✅ | ✅ | — | — |
| `asset.read` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| `asset.write` | — | — | — | ✅ | ✅ | — | — |
| `asset.import` | — | — | — | ✅ | ✅ | — | — |
| `asm.read` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| `asm.import` | — | — | — | ✅ | ✅ | — | — |
| `vuln.read` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| `vuln.triage` | — | ✅ | ✅ | ✅ | ✅ | — | — |
| `vuln.exception` | — | — | — | ✅ | ✅ | — | — |
| `event.search` | — | ✅ | ✅ | ✅ | ✅ | — | — |
| `event.ingest` (token) | — | — | — | — | — | — | — |
| `alert.read` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| `alert.triage` | — | ✅ | ✅ | ✅ | ✅ | — | — |
| `incident.read` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| `incident.write` | — | — | ✅ | ✅ | ✅ | — | — |
| `incident.evidence.read` | — | — | ✅ | ✅ | ✅ | ✅ | — |
| `incident.report` | — | — | ✅ | ✅ | ✅ | ✅ | — |
| `cti.read` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| `cti.write` | — | ✅ | ✅ | ✅ | ✅ | — | — |
| `rule.read` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| `rule.draft` | — | ✅ | ✅ | ✅ | ✅ | — | — |
| `rule.publish` | — | — | — | ✅ | ✅ | — | — |
| `playbook.read` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| `playbook.write` | — | — | — | ✅ | ✅ | — | — |
| `playbook.execute` | — | — | ✅ | ✅ | ✅ | — | — |
| `approval.decide` | — | — | — | ✅ | ✅ | — | — |
| `autonomy.read` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| `autonomy.evaluate` | — | — | ✅ | ✅ | ✅ | — | — |
| `autonomy.execute` | — | — | ✅ | ✅ | ✅ | — | — |
| `autonomy.policy.write` | — | — | — | ✅ | ✅ | — | — |
| `killswitch.activate` | — | — | — | ✅ | ✅ | — | ✅ (global) |
| `connector.read` | — | — | ✅ | ✅ | ✅ | — | — |
| `connector.write` | — | — | — | ✅ | ✅ | — | — |
| `connector.secret.rotate` | — | — | — | ✅ | ✅ | — | — |
| `ai.use` | — | ✅ | ✅ | ✅ | ✅ | — | — |
| `ai.configure` | — | — | — | ✅ | ✅ | — | ✅ (global) |
| `agent.run` | — | ✅ | ✅ | ✅ | ✅ | — | — |
| `mcp.invoke` | — | — | — | ✅ | ✅ | — | — |
| `compliance.read` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| `compliance.evidence.submit` | — | — | ✅ | ✅ | ✅ | — | — |
| `compliance.evidence.review` | — | — | — | — | ✅ | ✅ | — |
| `compliance.assess` | — | — | — | ✅ | ✅ | ✅ | — |
| `report.generate` | — | — | — | ✅ | ✅ | ✅ | — |
| `audit.read` | — | — | — | ✅ | ✅ | ✅ | ✅ (plataforma) |
| `audit.verify` | — | — | — | ✅ | ✅ | ✅ | ✅ |
| `settings.write` | — | — | — | ✅ | ✅ | — | ✅ (global) |
| `backup.run` | — | — | — | — | ✅ | — | ✅ |
| `break_glass.request` | — | — | — | — | — | — | ✅ |

**Reglas de composición**
- Varios roles ⇒ **unión** de permisos, con una excepción: si el rol activo es `auditor`, se eliminan todos los permisos de escritura (`auditor` es un modo de solo lectura).
- `platform_admin` **no** hereda permisos de dominio; solo los ejerce con `break-glass` activo.
- `service` (PAT) no tiene roles: solo scopes de token.

---

## 3. SCOPES DE TOKEN (SERVICIO)

| Scope | Permite | No permite |
| :--- | :--- | :--- |
| `assets:read` | `GET /assets*`, `GET /zones` | escribir activos |
| `assets:write` | `POST/PATCH/DELETE /assets*` | leer evidencias |
| `events:write` | `POST /events/webhook/*`, `/edge/ingest` | buscar eventos |
| `events:read` | `POST /events/search`, SSE | ingesta |
| `incidents:read` | `GET /incidents*` | cambiar estado |
| `incidents:write` | `POST/PATCH /incidents*` | aprobar acciones |
| `playbooks:execute` | `POST /playbooks/{id}/execute` (sujeto a política) | publicar playbooks |
| `compliance:read` | `GET /compliance/*`, `/reports/*` | aprobar evidencias |
| `alerts:read` | `GET /alerts*` | triage |

Un token nunca puede: (`a`) llamar a `/auth/*`, (`b`) gestionar miembros, (`c`) rotar secretos de conector, (`d`) activar kill switches, (`e`) aprobar acciones, (`f`) leer auditoría.

---

## 4. MATRIZ ENDPOINT → PERMISO (extracto normativo)

| Endpoint | Método | Permiso | Scope | Notas |
| :--- | :--- | :--- | :--- | :--- |
| `/auth/login` | POST | `public` | — | rate-limited |
| `/auth/me` | GET | `authenticated` | self | |
| `/organizations/{id}/members` | GET | `member.read` | org | |
| `/organizations/{id}/members` | POST | `member.invite` | org | no puede invitar `owner` salvo `owner` |
| `/assets` | GET | `asset.read` | org | |
| `/assets` | POST | `asset.write` | org | |
| `/assets/import` | POST | `asset.import` | org | |
| `/vulnerabilities/{id}/exception` | POST | `vuln.exception` | org | solicitante ≠ aprobador |
| `/events/search` | POST | `event.search` | org | |
| `/events/webhook/{id}` | POST | `hmac` | org (conector) | sin sesión |
| `/detection-rules/{id}/publish` | POST | `rule.publish` | org | |
| `/playbooks/{id}/execute` | POST | `playbook.execute` | org | + política |
| `/approvals/{id}/decide` | POST | `approval.decide` | org | + no-autoaprobación |
| `/autonomy/actions` | POST | `autonomy.execute` | org | + política + kill switch |
| `/autonomy/kill-switches` | POST | `killswitch.activate` | org | `owner`/`admin` |
| `/mcp/tools/{name}/invoke` | POST | `mcp.invoke` | org | + allowlist + política |
| `/compliance/evidence/{id}/review` | POST | `compliance.evidence.review` | org | solicitante ≠ revisor |
| `/audit/verify` | GET | `audit.verify` | org | |
| `/settings` | PATCH | `settings.write` | org | |
| `/backup/run` | POST | `backup.run` | global | `platform_admin` |

La lista completa se materializa en `permissions.py` como tabla declarativa y se verifica con `test_rbac_matrix.py` (una celda por permiso × rol).

---

## 5. FLUJO DE AUTORIZACIÓN

```text
1. Resolver identidad: cookie hs_session | Bearer PAT.
2. Si Bearer: validar token, expiración, estado, scopes → no hay roles.
3. Resolver organización: header X-Organization-Id (obligatorio si scope=org).
4. Verificar membership activa → si no, 403 organization_forbidden.
5. Si break-glass: validar concesión vigente, TTL, justificación → añadir contexto auditado.
6. Resolver permisos efectivos (unión de roles; reducción si auditor).
7. Comprobar required_permission → si falta, 403 forbidden con required_permission.
8. Cargar recurso filtrando por organization_id → si no existe, 404.
9. (Opcional) verificar ownership/atributo (p.ej. assignee) → 403 si procede.
10. Ejecutar caso de uso; auditar si la acción es sensible.
```

---

## 6. BREAK-GLASS (SOPORTE DE PLATAFORMA)

| Regla | Valor |
| :--- | :--- |
| Solicitante | `platform_admin` |
| Aprobador | `owner` de la org objetivo (o dos `platform_admin` si la org está inaccesible y hay incidente declarado) |
| Justificación | ≥40 caracteres, vinculada a ticket |
| TTL | ≤60 min, no renovable automáticamente |
| Alcance | Solo lectura por defecto; escritura requiere aprobación explícita adicional |
| Visibilidad | Banner persistente en la UI de la org; entrada en auditoría; notificación a `owner` |
| Registro | `break_glass_grant` con `granted_by`, `approved_by`, `expires_at`, `ticket_ref` |

---

## 7. DEFENSA EN PROFUNDIDAD

| Capa | Control |
| :--- | :--- |
| Router | `Depends(require_permission(...))` obligatorio; test que detecta routers sin guard |
| Servicio | Verificación de pertenencia del recurso antes de mutar |
| Repositorio | `organization_id` obligatorio en la firma |
| Base de datos | RLS opcional en tablas críticas (`events`, `incidents`, `evidence`) |
| Auditoría | Acciones sensibles y denegaciones registradas |
| UI | Ocultación + explicación de permiso requerido (no es control de seguridad) |

---

## 8. PRUEBAS OBLIGATORIAS

| Test | Cobertura |
| :--- | :--- |
| `test_rbac_matrix.py` | Todas las celdas rol × permiso |
| `test_tenant_isolation.py` | Todos los recursos: list, get, update, delete, export, SSE |
| `test_endpoint_guards.py` | Todo router tiene guard declarado (AST/registry) |
| `test_break_glass.py` | TTL, aprobación, banner, auditoría, expiración |
| `test_token_scopes.py` | Cada scope permite lo declarado y nada más |
| `test_separation_of_duties.py` | Aprobador ≠ solicitante en excepciones, evidencias, acciones |

## 9. CRITERIOS DE ACEPTACIÓN

`AC-10`, `AC-11`, `AC-12`, `AC-122` (aislamiento y matriz), `AC-58` (evidencias), `AC-AUTH-06` (break-glass), `AC-AUTH-07` (scopes).

## 10. EVIDENCIA

1. Tabla generada por `test_rbac_matrix.py` con celdas y resultado.
2. Informe de cobertura de guards por router.
3. Test de break-glass con expiración y auditoría.
4. Test de scopes por token.
