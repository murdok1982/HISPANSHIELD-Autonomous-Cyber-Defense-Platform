# CONTRATO REST `/api/v1`

- **Documento:** `specs/api/rest-contract.md`
- **Estado:** `LOCKED` v1.0
- **OpenAPI:** generado por FastAPI en `/api/v1/openapi.json` (fuente ejecutable); este documento es el contrato normativo y la guía de consumo.
- **Catálogo humano:** `docs/api-reference.md`

---

## 1. CONVENCIONES GENERALES

| Aspecto | Regla |
| :--- | :--- |
| Base | `/api/v1` |
| Formato | JSON UTF-8 (`application/json`); binarios con `Content-Type` específico |
| Fechas | ISO 8601 UTC con `Z` (`2026-11-26T10:00:00Z`) |
| IDs | UUIDv7 en string |
| Nombres | `snake_case` en JSON (coherente con Python) |
| Paginación | Cursor: `?cursor=<opaque>&limit=<1..200>` → `{data[], meta:{next_cursor, total_estimate}}` |
| Orden | Por defecto `created_at DESC`; `?sort=` con allowlist por recurso |
| Errores | `{error:{code, message, fields?:[{path,message}], request_id}}` |
| Idempotencia | `Idempotency-Key` en POST de ingesta/ejecución/import; TTL 24 h |
| Correlación | `X-Request-Id` aceptado (validado) o generado; devuelto siempre |
| Versionado | `/v1`; cambio incompatible → `/v2` con solapamiento ≥1 release |
| Compresión | `gzip`/`br` para respuestas >1 KB |
| Límites | Body 10 MB (50 MB evidencias); rate limit por usuario/org/token |

---

## 2. AUTENTICACIÓN

| Modo | Cabeceras | Uso |
| :--- | :--- | :--- |
| Sesión | `Cookie: hs_session=...` + `X-CSRF-Token` en mutaciones | UI |
| Bearer | `Authorization: Bearer hs_pat_...` | Automatización (sin CSRF) |
| Webhook | `X-HS-Signature: sha256=...`, `X-HS-Timestamp` | Ingesta |
| Edge | mTLS + `X-HS-Signature` + `X-HS-Sequence` | Gateway |

**CSRF:** obligatorio en `POST/PUT/PATCH/DELETE` con cookie. Token en cookie `hs_csrf`, header `X-CSRF-Token`. Error: `403 csrf_failed`.

---

## 3. TENANCY

`X-Organization-Id: <uuid>` obligatorio en rutas org-scoped (todas salvo auth, setup, health, metrics). Validaciones: formato → `400`; membership → `403 organization_forbidden`; recurso ajeno → `404 not_found`.

---

## 4. CÓDIGOS DE ERROR ESTABLES

| `code` | HTTP | Significado |
| :--- | :--- | :--- |
| `validation_error` | 422 | Esquema inválido; `fields[]` con path |
| `bad_request` | 400 | Petición malformada (JSON inválido, cabecera ausente) |
| `unauthenticated` | 401 | Sin sesión/token válido |
| `invalid_credentials` | 401 | Login fallido (uniforme) |
| `session_invalid` | 401 | Sesión revocada/expirada |
| `csrf_failed` | 403 | CSRF ausente/incorrecto |
| `forbidden` | 403 | Permiso insuficiente (`required_permission` en detalle) |
| `organization_forbidden` | 403 | Sin membership |
| `organization_suspended` | 403 | Org suspendida |
| `not_found` | 404 | Recurso inexistente o de otra org |
| `conflict` | 409 | Estado incompatible |
| `invalid_transition` | 409 | Transición de estado no permitida |
| `duplicate_asset` | 409 | Duplicado con `existing_id` |
| `idempotency_conflict` | 409 | Misma clave, cuerpo distinto |
| `legal_hold_active` | 409 | Bloqueo por custodia |
| `evidence_integrity_failed` | 409 | Hash no coincide |
| `payload_too_large` | 413 | Límite de tamaño |
| `unsupported_media_type` | 415 | MIME no permitido |
| `invitation_expired` | 410 | Invitación caducada |
| `rate_limited` | 429 | Límite; `Retry-After` |
| `ai_budget_exceeded` | 429 | Presupuesto IA; `resets_at` |
| `autonomy_halted` | 429 | Kill switch activo |
| `dependency_unavailable` | 503 | BD/proveedor caído |
| `ai_unavailable` | 503 | Sin proveedor IA |

---

## 5. CATÁLOGO DE ENDPOINTS

### 5.1 Autenticación y usuarios

| Método | Ruta | Permiso | Notas |
| :--- | :--- | :--- | :--- |
| POST | `/auth/login` | público | `200` / `202 mfa_required` |
| POST | `/auth/mfa/verify` | challenge | `200` |
| POST | `/auth/mfa/enroll` · `/activate` | sesión | secreto una vez |
| POST | `/auth/logout` | sesión | `204` |
| GET | `/auth/me` | sesión | user + memberships + permisos |
| POST | `/auth/password/change` | sesión | revoca otras sesiones |
| GET/DELETE | `/auth/sessions` · `/auth/sessions/{id}` | sesión | listado/revocación |
| POST | `/setup` | público si vacío | bootstrap |
| GET/PATCH | `/users/{id}` | `self`/`member.role.write` | perfil |
| GET/POST/DELETE | `/users/{id}/tokens` | `self`/`admin` | PAT |

### 5.2 Organizaciones

| Método | Ruta | Permiso |
| :--- | :--- | :--- |
| GET/POST | `/organizations` | autenticado / `platform_admin` |
| GET/PATCH/DELETE | `/organizations/{id}` | miembro / `org.settings.write` / `org.delete` |
| GET/POST | `/organizations/{id}/members` | `member.read` / `member.invite` |
| PATCH/DELETE | `/organizations/{id}/members/{user_id}` | `member.role.write` |
| POST | `/invitations/{token}/accept` | autenticado |
| GET/PATCH | `/organizations/{id}/settings` | `admin` |

### 5.3 Activos, zonas, ASM

| Método | Ruta | Permiso |
| :--- | :--- | :--- |
| GET/POST | `/assets` | `asset.read` / `asset.write` |
| GET/PATCH/DELETE | `/assets/{id}` | `asset.read` / `asset.write` |
| POST | `/assets/{id}/restore` | `asset.write` |
| POST | `/assets/import` | `asset.import` |
| GET/POST/DELETE | `/assets/{id}/relationships` | `asset.read` / `asset.write` |
| GET | `/assets/{id}/graph` | `asset.read` |
| GET/POST/PATCH/DELETE | `/zones` | `asset.read` / `asset.write` |
| POST | `/assets/{id}/iot` · `/ot` | `asset.write` |
| GET | `/attack-surface` · `/diffs` | `asm.read` |
| POST | `/attack-surface/import` · `/ranges` | `asm.import` |
| GET | `/attack-surface/export` | `asm.read` |

### 5.4 Vulnerabilidades

| Método | Ruta | Permiso |
| :--- | :--- | :--- |
| GET | `/vulnerabilities` · `/stats` | `vuln.read` |
| GET | `/vulnerabilities/{id}` | `vuln.read` |
| PATCH | `/vulnerabilities/{id}/status` · `/assignee` | `vuln.triage` |
| POST | `/vulnerabilities/{id}/exception` | `vuln.exception` |
| POST | `/vulnerabilities/{id}/false-positive` | `vuln.triage` |
| POST | `/vulnerabilities/import` | `vuln.triage` |
| GET | `/vulnerabilities/export` | `vuln.read` |

### 5.5 SIEM, reglas, alertas

| Método | Ruta | Permiso |
| :--- | :--- | :--- |
| POST | `/events/webhook/{connector_id}` | HMAC |
| POST | `/events/search` | `event.search` |
| GET | `/events/stream` (SSE) | `event.search` |
| POST | `/edge/ingest` | mTLS+HMAC |
| GET/POST | `/detection-rules` | `rule.read` / `rule.draft` |
| POST | `/detection-rules/{id}/versions` · `/publish` · `/test` | `rule.draft` / `rule.publish` / `rule.draft` |
| GET | `/alerts` | `alert.read` |
| PATCH | `/alerts/{id}` | `alert.triage` |
| POST | `/alerts/{id}/promote` | `incident.write` |

### 5.6 Incidentes, evidencias, forense

| Método | Ruta | Permiso |
| :--- | :--- | :--- |
| GET/POST | `/incidents` | `incident.read` / `incident.write` |
| GET/PATCH | `/incidents/{id}` | `incident.read` / `incident.write` |
| POST | `/incidents/{id}/state` · `/timeline` · `/evidence` · `/report` | `incident.write` |
| GET | `/incidents/{id}/timeline` | `incident.read` |
| POST | `/incidents/{id}/merge` · `/split` | `admin` |
| GET | `/evidence/{id}` | `incident.evidence.read` |
| GET/POST | `/forensics/cases` | `incident.write` |
| POST | `/forensics/cases/{id}/evidence` · `/export` · `/legal-hold` | `incident.write` / `owner` |
| GET | `/forensics/cases/{id}/timeline` | `incident.read` |

### 5.7 CTI

| Método | Ruta | Permiso |
| :--- | :--- | :--- |
| GET/POST | `/threat-intel/indicators` · `/actors` · `/campaigns` | `cti.read` / `cti.write` |
| POST | `/threat-intel/stix/import` | `cti.write` |
| GET | `/threat-intel/stix/export` | `cti.read` |
| GET/POST | `/threat-intel/feeds` | `cti.read` / `connector.write` |
| POST | `/threat-intel/feeds/{id}/sync` | `connector.write` |
| GET/POST/DELETE | `/threat-intel/whitelist` | `cti.write` |
| GET | `/threat-intel/matches` | `cti.read` |

### 5.8 SOAR

| Método | Ruta | Permiso |
| :--- | :--- | :--- |
| GET/POST | `/playbooks` | `playbook.read` / `playbook.write` |
| GET/PATCH | `/playbooks/{id}` | `playbook.read` / `playbook.write` |
| POST | `/playbooks/{id}/versions` · `/publish` · `/validate` | `playbook.write` |
| POST | `/playbooks/{id}/execute` | `playbook.execute` |
| GET | `/executions` · `/executions/{id}` | `playbook.read` |
| POST | `/executions/{id}/cancel` · `/compensate` | `playbook.execute` |
| GET | `/approvals` | `approval.decide` |
| POST | `/approvals/{id}/decide` | `approval.decide` |

### 5.9 Autonomía

| Método | Ruta | Permiso |
| :--- | :--- | :--- |
| GET/POST | `/autonomy/policies` | `autonomy.read` / `autonomy.policy.write` |
| POST | `/autonomy/evaluate` | `autonomy.evaluate` |
| POST | `/autonomy/actions` | `autonomy.execute` |
| GET | `/autonomy/actions/{id}` | `autonomy.read` |
| GET/POST | `/autonomy/kill-switches` | `autonomy.read` / `killswitch.activate` |
| POST | `/autonomy/kill-switches/{id}/activate` | `killswitch.activate` |

### 5.10 IA y MCP

| Método | Ruta | Permiso |
| :--- | :--- | :--- |
| GET/POST | `/ai/providers` | `ai.configure` |
| POST | `/ai/providers/{id}/test` | `ai.configure` |
| GET | `/ai/models` | `ai.use` |
| POST | `/ai/chat` · `/ai/rag/query` | `ai.use` |
| GET/POST | `/ai/documents` | `ai.configure` |
| GET/POST | `/agents` · `/agents/{id}/runs` | `agent.run` |
| GET/POST | `/mcp/servers` · `/mcp/tools` | `mcp.invoke` |
| POST | `/mcp/tools/{name}/invoke` | `mcp.invoke` |

### 5.11 Cloud, conectores, protocolos

| Método | Ruta | Permiso |
| :--- | :--- | :--- |
| GET/POST | `/cloud/accounts` | `connector.read` / `connector.write` |
| POST | `/cloud/accounts/{id}/verify` · `/scan` | `connector.write` |
| GET | `/cloud/accounts/{id}/posture` · `/cloud/resources` · `/cloud/findings` | `connector.read` |
| GET/POST/PATCH/DELETE | `/connectors` | `connector.read` / `connector.write` |
| POST | `/connectors/{id}/test` · `/rotate-secret` | `connector.secret.rotate` |
| GET | `/connectors/{id}/health` · `/errors` | `connector.read` |
| GET | `/protocols` · `/protocols/compatibility` | `connector.read` |

### 5.12 Cumplimiento, informes, auditoría, plataforma

| Método | Ruta | Permiso |
| :--- | :--- | :--- |
| GET | `/compliance/frameworks` · `/controls` · `/mappings` | `compliance.read` |
| POST | `/compliance/evidence` · `/evidence/{id}/review` | `compliance.evidence.submit` / `.review` |
| GET/POST | `/compliance/assessments` · `/assessments/{id}/run` | `compliance.assess` |
| GET/POST | `/compliance/nis2/incidents` · `/gdpr/ropa` · `/gdpr/dpia` | `compliance.read` / `compliance.assess` |
| POST | `/reports` · GET `/reports/{id}` · `/download` | `report.generate` / `compliance.read` |
| GET | `/audit` · `/audit/verify` · `/audit/actions/{id}` | `audit.read` / `audit.verify` |
| GET | `/metrics/summary` | `org.read` |
| GET | `/metrics` (Prometheus) | red interna |
| GET | `/healthz` · `/readyz` | red interna |
| GET/PATCH | `/settings` | `settings.write` |

---

## 6. SSE

`GET /api/v1/events/stream?types=alert.created,event.ingested&severity_gte=3`

```text
event: alert.created
id: 0192c3...
data: {"alert_id":"...","severity":"high","title":"...","asset_id":"..."}

: heartbeat
```

| Regla | Detalle |
| :--- | :--- |
| Auth | Sesión o Bearer; filtro forzado a la org |
| Reconnect | `Last-Event-ID` soportado; replay de últimos 5 min |
| Heartbeat | Cada 15 s |
| Límite | 5 conexiones por usuario; `429` al exceder |
| Backpressure | Si el cliente no lee, se cierra con `slow_consumer` |

---

## 7. EJEMPLOS DE ERROR

```json
{
  "error": {
    "code": "forbidden",
    "message": "Permiso insuficiente para ejecutar acciones autónomas",
    "required_permission": "autonomy.execute",
    "request_id": "req_01J8Z..."
  }
}
```

```json
{
  "error": {
    "code": "validation_error",
    "message": "Payload inválido",
    "fields": [
      {"path": "criticality", "message": "debe estar entre 1 y 5"},
      {"path": "attributes.purdue_level", "message": "requerido para activos OT"}
    ],
    "request_id": "req_01J8Z..."
  }
}
```

---

## 8. RATE LIMITS

| Ámbito | Límite | Ventana |
| :--- | :--- | :--- |
| Login | 5 | 15 min por email+IP |
| MFA verify | 5 | 5 min por challenge |
| API general | 600 | 1 min por usuario |
| API por token | 300 | 1 min |
| Ingesta webhook | 10.000 eventos | 1 min por conector |
| IA | 60 | 1 min por org |
| Export | 5 | 1 min por usuario |

Cabeceras: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, `Retry-After`.

---

## 9. COMPATIBILIDAD Y DEPRECACIÓN

- Campos nuevos son aditivos; los clientes deben ignorar desconocidos.
- Campos eliminados pasan por `deprecated: true` en OpenAPI durante ≥1 release.
- Un cambio de semántica requiere nueva versión de endpoint o de parámetro.
- Los errores `code` son estables; el `message` puede cambiar (no parsear mensajes).

---

## 10. CRITERIOS DE ACEPTACIÓN

`AC-05` (scopes), `AC-10..AC-12` (tenancy/RBAC), `AC-26` (idempotencia), `AC-34/35` (webhook), `AC-101` (SSE), `AC-117..AC-124` (gates).

## 11. EVIDENCIA

1. `openapi.json` generado y validado (sin `$ref` roto).
2. Test de contrato por endpoint (200/4xx esperados).
3. Test de idempotencia y de rate limit.
4. Ejemplo de SSE con reconexión.
5. Catálogo `docs/api-reference.md` sincronizado.
