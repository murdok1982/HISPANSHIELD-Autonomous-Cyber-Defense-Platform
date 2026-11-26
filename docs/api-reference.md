# REFERENCIA DE API

- **Documento:** `docs/api-reference.md`
- **Estado:** `APPROVED` v1.0
- **Contrato normativo:** `specs/api/rest-contract.md`
- **OpenAPI en runtime:** `GET /api/v1/openapi.json` · Swagger UI en `/api/v1/docs` (solo redes internas)
- **Base:** `/api/v1`

---

## 1. AUTENTICACIÓN RÁPIDA

```bash
# Login (cookie + CSRF)
curl -c jar.txt -X POST https://hs.example.eu/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"analyst@example.eu","password":"***"}'

# Token CSRF para mutaciones
CSRF=$(grep hs_csrf jar.txt | awk '{print $7}')

# Petición autenticada
curl -b jar.txt -H "X-Organization-Id: $ORG" \
  https://hs.example.eu/api/v1/assets?limit=20
```

```bash
# Bearer (automatización, sin CSRF)
curl -H "Authorization: Bearer hs_pat_xxx" \
  -H "X-Organization-Id: $ORG" \
  https://hs.example.eu/api/v1/assets
```

---

## 2. CONVENCIONES

| Elemento | Regla |
| :--- | :--- |
| Paginación | `?cursor=<opaque>&limit=20` → `{data[], meta:{next_cursor,total_estimate}}` |
| Filtros | Query params tipados; validados; error `422` con `path` |
| Orden | `?sort=field:asc|desc` (allowlist por recurso) |
| Errores | `{error:{code,message,fields?,request_id}}` |
| Idempotencia | `Idempotency-Key` en POST de ingesta/ejecución/import |
| Correlación | `X-Request-Id` (opcional, devuelto siempre) |
| Fechas | ISO 8601 UTC |

---

## 3. MÓDULOS Y ENDPOINTS

### 3.1 `auth` — autenticación

| Método | Ruta | Descripción |
| :--- | :--- | :--- |
| POST | `/auth/login` | `200` sesión o `202 mfa_required` |
| POST | `/auth/mfa/verify` | Verifica TOTP o recovery code |
| POST | `/auth/mfa/enroll` | Devuelve `otpauth_url` y secreto una vez |
| POST | `/auth/mfa/activate` | Activa y devuelve recovery codes |
| POST | `/auth/logout` | Revoca sesión actual |
| GET | `/auth/me` | Usuario, memberships, permisos |
| POST | `/auth/password/change` | Cambia y revoca otras sesiones |
| GET | `/auth/sessions` | Sesiones activas |
| DELETE | `/auth/sessions/{id}` | Revoca una sesión |

### 3.2 `organizations` y `users`

| Método | Ruta | Descripción |
| :--- | :--- | :--- |
| POST | `/setup` | Bootstrap inicial (solo si no hay orgs) |
| GET/POST | `/organizations` | Lista / crea |
| GET/PATCH/DELETE | `/organizations/{id}` | Detalle / actualiza / soft delete |
| GET/POST | `/organizations/{id}/members` | Lista / invita |
| PATCH/DELETE | `/organizations/{id}/members/{user_id}` | Cambia rol / elimina |
| POST | `/invitations/{token}/accept` | Acepta invitación |
| GET/PATCH | `/organizations/{id}/settings` | Settings de organización |
| GET/PATCH | `/users/{id}` | Perfil |
| GET/POST/DELETE | `/users/{id}/tokens` | PAT |

### 3.3 `assets` y `zones`

| Método | Ruta | Descripción |
| :--- | :--- | :--- |
| GET/POST | `/assets` | Lista con filtros / crea |
| GET/PATCH/DELETE | `/assets/{id}` | Detalle / actualiza / soft delete |
| POST | `/assets/{id}/restore` | Restaura |
| POST | `/assets/import` | CSV/JSON `207` |
| GET/POST/DELETE | `/assets/{id}/relationships` | Grafo |
| GET | `/assets/{id}/graph?depth=2` | Subgrafo |
| POST | `/assets/{id}/iot` · `/ot` | Perfil especializado |
| GET/POST/PATCH/DELETE | `/zones` | Zonas |

```bash
curl -X POST https://hs.example.eu/api/v1/assets \
  -b jar.txt -H "X-Organization-Id: $ORG" -H "X-CSRF-Token: $CSRF" \
  -H 'Content-Type: application/json' \
  -d '{"name":"srv-db-01","kind":"host","criticality":5,"owner":"ops@example.eu","tags":["produccion"],"attributes":{"ip":"10.0.4.12","os":"rhel9"},"source":"manual"}'
```

### 3.4 `attack_surface`

| Método | Ruta | Descripción |
| :--- | :--- | :--- |
| GET | `/attack-surface` | Observaciones |
| GET | `/attack-surface/diffs` | Cambios de exposición |
| POST | `/attack-surface/import` | Importa escáner |
| GET/POST | `/attack-surface/ranges` | Alcance autorizado |
| GET | `/attack-surface/export?format=stix2.1` | Exporta |
| GET | `/jobs/{id}` | Estado de job |

### 3.5 `vulnerabilities`

| Método | Ruta | Descripción |
| :--- | :--- | :--- |
| GET | `/vulnerabilities` | Lista priorizada |
| GET | `/vulnerabilities/{id}` | Detalle + `score_breakdown` |
| GET | `/vulnerabilities/stats` | Agregados |
| PATCH | `/vulnerabilities/{id}/status` | Transición |
| PATCH | `/vulnerabilities/{id}/assignee` | Asignación |
| POST | `/vulnerabilities/{id}/exception` | Aceptación de riesgo |
| POST | `/vulnerabilities/{id}/false-positive` | Requiere evidencia |
| POST | `/vulnerabilities/import` | Nessus/OpenVAS/Trivy |
| GET | `/vulnerabilities/export` | CSV/JSON |

### 3.6 `events` y `detections`

| Método | Ruta | Descripción |
| :--- | :--- | :--- |
| POST | `/events/webhook/{connector_id}` | Ingesta firmada |
| POST | `/edge/ingest` | Ingesta edge (mTLS) |
| POST | `/events/search` | Búsqueda |
| GET | `/events/stream` | SSE |
| GET/POST | `/detection-rules` | Reglas |
| POST | `/detection-rules/{id}/versions` | Nueva versión |
| POST | `/detection-rules/{id}/publish` | Publica |
| POST | `/detection-rules/{id}/test` | Prueba sin alertar |

```bash
curl -X POST https://hs.example.eu/api/v1/events/search \
  -b jar.txt -H "X-Organization-Id: $ORG" -H "X-CSRF-Token: $CSRF" \
  -H 'Content-Type: application/json' \
  -d '{"from":"2026-11-25T00:00:00Z","to":"2026-11-26T00:00:00Z","filters":{"src_endpoint.ip":"198.51.100.23","severity_id_gte":3},"limit":100}'
```

### 3.7 `alerts` e `incidents`

| Método | Ruta | Descripción |
| :--- | :--- | :--- |
| GET | `/alerts` | Cola |
| PATCH | `/alerts/{id}` | ack/resolve/suppress |
| POST | `/alerts/{id}/promote` | Crea/vincula incidente |
| GET/POST | `/incidents` | Lista / crea |
| GET/PATCH | `/incidents/{id}` | Detalle / actualiza |
| POST | `/incidents/{id}/state` | Transición |
| GET/POST | `/incidents/{id}/timeline` | Timeline |
| POST | `/incidents/{id}/evidence` | Evidencia |
| GET | `/evidence/{id}` | Descarga con hash |
| POST | `/incidents/{id}/merge` · `/split` | Fusión/división |
| POST | `/incidents/{id}/report` | Informe |

### 3.8 `threat_intel`

| Método | Ruta | Descripción |
| :--- | :--- | :--- |
| GET/POST | `/threat-intel/indicators` | Indicadores |
| GET/POST | `/threat-intel/actors` · `/campaigns` | Actores y campañas |
| POST | `/threat-intel/stix/import` | Bundle |
| GET | `/threat-intel/stix/export` | Bundle |
| GET/POST | `/threat-intel/feeds` | Feeds |
| POST | `/threat-intel/feeds/{id}/sync` | Sincroniza |
| GET/POST/DELETE | `/threat-intel/whitelist` | Supresión |
| GET | `/threat-intel/matches` | Coincidencias |

### 3.9 `playbooks`, `executions`, `approvals`

| Método | Ruta | Descripción |
| :--- | :--- | :--- |
| GET/POST | `/playbooks` | Lista / crea |
| POST | `/playbooks/{id}/validate` | Valida DAG |
| POST | `/playbooks/{id}/versions` · `/publish` | Versiona / publica |
| POST | `/playbooks/{id}/execute` | Ejecuta (`dry_run` opcional) |
| GET | `/executions` · `/executions/{id}` | Estado y pasos |
| POST | `/executions/{id}/cancel` · `/compensate` | Cancela / revierte |
| GET | `/approvals` | Pendientes |
| POST | `/approvals/{id}/decide` | Aprueba / deniega |

```bash
curl -X POST https://hs.example.eu/api/v1/playbooks/$PB/execute \
  -b jar.txt -H "X-Organization-Id: $ORG" -H "X-CSRF-Token: $CSRF" \
  -H 'Idempotency-Key: exec-2026-11-26-001' \
  -d '{"input":{"incident_id":"'$INC'"},"dry_run":true}'
```

### 3.10 `autonomy`

| Método | Ruta | Descripción |
| :--- | :--- | :--- |
| GET/POST | `/autonomy/policies` | Políticas |
| POST | `/autonomy/evaluate` | Evaluación sin ejecutar |
| POST | `/autonomy/actions` | Solicita acción |
| GET | `/autonomy/actions/{id}` | Decisión + resultado |
| GET/POST | `/autonomy/kill-switches` | Lista / crea |
| POST | `/autonomy/kill-switches/{id}/activate` | Activa/desactiva |

```bash
curl -X POST https://hs.example.eu/api/v1/autonomy/evaluate \
  -b jar.txt -H "X-Organization-Id: $ORG" -H "X-CSRF-Token: $CSRF" \
  -d '{"action_type":"isolate_host","targets":["'$ASSET'"],"parameters":{},"justification":"ransomware confirmado"}'
```

Respuesta:
```json
{"decision":"deny","reason":"blast_radius_exceeded","required_level":"A3","policy_version":4,"decision_id":"0192c1..."}
```

### 3.11 `ai`, `agents`, `mcp`

| Método | Ruta | Descripción |
| :--- | :--- | :--- |
| GET/POST | `/ai/providers` | Proveedores |
| POST | `/ai/providers/{id}/test` | Prueba |
| GET | `/ai/models` | Modelos |
| POST | `/ai/chat` · `/ai/rag/query` | Inferencia |
| GET/POST | `/ai/documents` | Documentos |
| GET/POST | `/agents` | Definiciones |
| POST | `/agents/{id}/runs` | Lanza run |
| GET | `/agents/{id}/runs/{run_id}` | Estado y pasos |
| GET/POST | `/mcp/servers` · `/mcp/tools` | Registro |
| POST | `/mcp/tools/{name}/invoke` | Invoca tool |

### 3.12 `cloud`, `connectors`, `protocols`

| Método | Ruta | Descripción |
| :--- | :--- | :--- |
| GET/POST | `/cloud/accounts` | Cuentas |
| POST | `/cloud/accounts/{id}/verify` · `/scan` | Verifica / escanea |
| GET | `/cloud/accounts/{id}/posture` | Postura |
| GET | `/cloud/resources` · `/findings` | Inventario / hallazgos |
| GET/POST/PATCH/DELETE | `/connectors` | CRUD |
| POST | `/connectors/{id}/test` · `/rotate-secret` | Prueba / rota |
| GET | `/connectors/{id}/health` · `/errors` | Salud |
| GET | `/protocols` · `/protocols/compatibility` | Registro |

### 3.13 `compliance`, `reports`, `audit`

| Método | Ruta | Descripción |
| :--- | :--- | :--- |
| GET | `/compliance/frameworks` · `/controls` · `/mappings` | Catálogo |
| POST | `/compliance/evidence` · `/evidence/{id}/review` | Evidencia |
| GET/POST | `/compliance/assessments` · `/assessments/{id}/run` | Evaluaciones |
| GET/POST | `/compliance/nis2/incidents` · `/gdpr/ropa` · `/gdpr/dpia` | Registros |
| POST | `/reports` · GET `/reports/{id}` · `/download` | Informes |
| GET | `/audit` · `/audit/verify` · `/audit/actions/{id}` | Auditoría |

```bash
curl -b jar.txt -H "X-Organization-Id: $ORG" \
  "https://hs.example.eu/api/v1/audit/verify?from=1&to=1000000"
# {"valid":true,"checked_entries":84213}
```

### 3.14 `metrics`, `settings`, `health`

| Método | Ruta | Descripción |
| :--- | :--- | :--- |
| GET | `/metrics/summary` | KPIs ejecutivos |
| GET | `/metrics` | Prometheus (red interna) |
| GET | `/healthz` · `/readyz` | Salud |
| GET/PATCH | `/settings` | Feature flags y configuración |

---

## 4. SSE

```bash
curl -N -b jar.txt -H "X-Organization-Id: $ORG" \
  "https://hs.example.eu/api/v1/events/stream?types=alert.created,event.ingested&severity_gte=3"
```

```text
event: alert.created
id: 0192c3...
data: {"alert_id":"0192...","severity":"high","title":"RDP brute force","asset_id":"0192..."}
```

Reconexión con `Last-Event-ID`; heartbeat cada 15 s; límite 5 conexiones por usuario.

---

## 5. CÓDIGOS DE ERROR FRECUENTES

| HTTP | `code` | Cuándo |
| :--- | :--- | :--- |
| 400 | `bad_request` | JSON inválido o cabecera ausente |
| 401 | `unauthenticated` / `session_invalid` | Sin sesión o expirada |
| 403 | `forbidden` / `csrf_failed` / `autonomy_halted` | Permiso, CSRF o kill switch |
| 404 | `not_found` | Inexistente o de otra org |
| 409 | `invalid_transition` / `idempotency_conflict` | Estado incompatible |
| 413 | `payload_too_large` | Límite de subida |
| 415 | `unsupported_media_type` | MIME no permitido |
| 422 | `validation_error` | Esquema |
| 429 | `rate_limited` / `ai_budget_exceeded` | Límite |
| 503 | `dependency_unavailable` / `ai_unavailable` | BD o IA |

---

## 6. RATE LIMITS

Cabeceras `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, `Retry-After`.

| Ámbito | Límite |
| :--- | :--- |
| Login | 5 / 15 min |
| API usuario | 600 / min |
| API token | 300 / min |
| Ingesta webhook | 10.000 eventos / min |
| IA | 60 / min por org |
| Export | 5 / min |

---

## 7. EJEMPLO COMPLETO: ALERTA → INCIDENTE → ACCIÓN

```bash
# 1. Buscar la alerta
curl -b jar.txt -H "X-Organization-Id: $ORG" \
  "https://hs.example.eu/api/v1/alerts?status=open&severity_gte=3" | jq '.data[0].id'

# 2. Promover a incidente
curl -X POST -b jar.txt -H "X-Organization-Id: $ORG" -H "X-CSRF-Token: $CSRF" \
  "https://hs.example.eu/api/v1/alerts/$ALERT/promote" -d '{}'

# 3. Evaluar contención
curl -X POST -b jar.txt -H "X-Organization-Id: $ORG" -H "X-CSRF-Token: $CSRF" \
  "https://hs.example.eu/api/v1/autonomy/evaluate" \
  -d '{"action_type":"isolate_host","targets":["'$ASSET'"],"justification":"ransomware"}'

# 4. Ejecutar si la decisión es allow
curl -X POST -b jar.txt -H "X-Organization-Id: $ORG" -H "X-CSRF-Token: $CSRF" \
  -H "Idempotency-Key: act-001" \
  "https://hs.example.eu/api/v1/autonomy/actions" \
  -d '{"action_type":"isolate_host","targets":["'$ASSET'"],"justification":"ransomware"}'

# 5. Verificar resultado
curl -b jar.txt -H "X-Organization-Id: $ORG" \
  "https://hs.example.eu/api/v1/autonomy/actions/$ACTION" | jq '.state, .verification'
```

---

## 8. VERSIONADO

- `/v1` estable; cambios aditivos no rompen.
- Campos obsoletos se marcan `deprecated` en OpenAPI durante ≥1 release.
- Cambio incompatible → `/v2` con solapamiento.
- Los `code` de error son estables; los `message` pueden cambiar.
