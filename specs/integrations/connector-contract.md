# CONTRATO DE CONECTORES

- **Documento:** `specs/integrations/connector-contract.md`
- **Estado:** `APPROVED` v1.0
- **Ámbito:** todo conector de entrada (pull/push) o de salida (acción) registrado en la plataforma y el edge gateway.

---

## 1. PRINCIPIOS

1. **Un contrato, muchos conectores.** El core no conoce detalles de vendor; conoce capacidades, configuración validada, salud y errores normalizados.
2. **Sin secretos en claro.** La configuración pública y los secretos viven separados; la API solo expone `has_secret`.
3. **Degradación honesta.** Un conector que falla se marca `degraded/failed` con causa; no produce datos inventados.
4. **Capacidad declarada = capacidad autorizada.** Un conector no puede ejecutar una acción que no declare; el broker de autonomía valida contra `capabilities[]`.
5. **Idempotencia obligatoria** en ingesta y acciones, con clave estable.
6. **Aislamiento por organización.** Un conector pertenece a una org; no hay conectores compartidos salvo los globales de solo lectura claramente marcados.

---

## 2. MANIFIESTO DEL CONECTOR

```json
{
  "key": "fortigate_syslog",
  "name": "FortiGate Syslog",
  "version": "1.0.0",
  "kind": "ingest",
  "transport": ["syslog_udp", "syslog_tcp"],
  "capabilities": ["events.read"],
  "config_schema": {
    "type": "object",
    "additionalProperties": false,
    "required": ["host", "port"],
    "properties": {
      "host": {"type": "string", "format": "hostname"},
      "port": {"type": "integer", "minimum": 1, "maximum": 65535, "default": 5514},
      "tls": {"type": "boolean", "default": false}
    }
  },
  "secrets_schema": {
    "type": "object",
    "additionalProperties": false,
    "properties": {"shared_secret": {"type": "string", "minLength": 32}}
  },
  "ocsf": {"default_class_uid": 4001, "mapping": "fortigate_v1"},
  "rate_limit": {"default_per_minute": 10000},
  "health_check": {"type": "passive", "stale_after_seconds": 300},
  "docs_url": "docs/connector-guide.md#fortigate"
}
```

| Campo | Obligatorio | Regla |
| :--- | :--- | :--- |
| `key` | Sí | `^[a-z][a-z0-9_]{2,48}$`, único global |
| `version` | Sí | SemVer; cambio incompatible → major |
| `kind` | Sí | `ingest` \| `action` \| `bidirectional` |
| `transport` | Sí | Al menos uno del registro de protocolos |
| `capabilities` | Sí | Subconjunto del catálogo (`events.read`, `assets.read`, `alerts.write`, `host.isolate`, `ip.block`, `user.disable`, `file.quarantine`, `ticket.create`, `cloud.posture.read`, `cti.read`) |
| `config_schema` | Sí | JSON Schema draft 2020-12 válido; sin `additionalProperties: true` |
| `secrets_schema` | Si `kind != ingest` pasivo | Igual |
| `ocsf.mapping` | Si `events.read` | Referencia a mapeador versionado |
| `rate_limit` | Recomendado | Entero >0 |
| `health_check` | Sí | `active` (endpoint) o `passive` (última ingesta) |

Un manifiesto inválido → `422 connector_manifest_invalid` y no entra en el catálogo (`AC-104`).

---

## 3. INTERFAZ DE EJECUCIÓN

Todo conector implementa el mismo protocolo interno (Python `Protocol`):

```python
class Connector(Protocol):
    key: str
    capabilities: frozenset[str]

    def validate_config(self, config: dict) -> None: ...
    def health(self) -> HealthResult: ...                  # state, latency_ms, detail
    async def test_connection(self) -> TestResult: ...      # sin efectos laterales
    async def pull(self, cursor: str | None, limit: int) -> PullResult: ...
    async def push(self, events: list[RawEvent]) -> PushResult: ...
    async def execute(self, action: str, params: dict, idempotency_key: str) -> ActionResult: ...
    async def verify(self, action_result: ActionResult) -> VerificationResult: ...
    async def compensate(self, action_result: ActionResult) -> CompensationResult: ...
```

**Reglas de implementación**
- `test_connection` nunca crea, modifica ni borra recursos.
- `execute` debe ser idempotente respecto a `idempotency_key` o declarar `idempotent: false` (lo que obliga a aprobación A4 para acciones no idempotentes).
- `verify` devuelve `verified | failed | inconclusive` con evidencia; `inconclusive` cuenta como fallo para rollback.
- `compensate` debe poder ejecutarse dos veces sin daño.
- Timeouts: `pull/push` 30 s, `execute` 60 s, `verify` 45 s (configurables por conector, techos duros).

---

## 4. NORMALIZACIÓN Y ERRORES

### 4.1 Ingesta
Todo evento se normaliza a OCSF antes de persistir. El conector puede devolver datos crudos, pero el mapeador es responsabilidad del conector y está versionado (`mapping_v1`). Un cambio de mapeo requiere nueva versión y test de regresión con muestra.

### 4.2 Errores normalizados

| `code` | Significado | Reintentable | Efecto |
| :--- | :--- | :--- | :--- |
| `auth_failed` | Credencial inválida o expirada | No | `failed`, alerta a `admin` |
| `forbidden` | Permisos insuficientes | No | `failed` + finding de configuración |
| `rate_limited` | Límite del proveedor | Sí (backoff) | `degraded` |
| `timeout` | Sin respuesta | Sí | `degraded` |
| `upstream_5xx` | Error del proveedor | Sí | `degraded` |
| `invalid_response` | Esquema inesperado | Sí (limitado) | `degraded` + log de muestra redactada |
| `schema_mismatch` | Configuración incompatible tras actualización | No | `failed` |
| `not_supported` | Acción no soportada por la versión | No | `403 action_not_supported` |
| `policy_denied` | Broker/política denegó | No | No se invoca el conector |
| `internal_error` | Fallo del adaptador | Sí | `degraded` + traza interna con `request_id` |

### 4.3 Circuit breaker
- 5 fallos consecutivos → `open`; `next_attempt_at = now + min(300, 5 * 2^(n-5))` segundos.
- Un éxito en `half_open` → `closed` y contador a cero.
- Estado visible en `/connectors/{id}/health` y en la UI (`AC-107`).

---

## 5. SALUD Y OBSERVABILIDAD

```json
{
  "connector_id": "0192...",
  "state": "degraded",
  "last_success_at": "2026-11-26T08:00:00Z",
  "last_attempt_at": "2026-11-26T08:15:00Z",
  "last_error": {"code": "timeout", "message": "upstream timeout after 30s", "at": "2026-11-26T08:15:00Z"},
  "consecutive_failures": 3,
  "next_attempt_at": "2026-11-26T08:20:00Z",
  "metrics": {"events_in_1h": 18234, "events_rejected_1h": 2, "latency_p95_ms": 220}
}
```

Métricas Prometheus expuestas: `hs_connector_up`, `hs_connector_events_total{result}`, `hs_connector_latency_seconds`, `hs_connector_failures_total{code}`.

---

## 6. SEGURIDAD DEL CONECTOR

| Requisito | Regla |
| :--- | :--- |
| Secretos | Fernet con `key_version`; rotación con re-cifrado; nunca en logs ni en respuestas |
| Destinos | Allowlist de esquemas (`https`, y `http` solo loopback para IA local); bloqueo de rangos privados salvo `allow_private_network=true` explícito por conector y org |
| TLS | Verificación obligatoria; `verify=false` prohibido; CA personalizada soportada |
| Webhooks entrantes | HMAC-SHA256 + timestamp ±300 s + `connector_id` allowlist |
| Rate limit | Por conector y por org; `429` con `Retry-After` |
| Auditoría | Alta, cambio de config, rotación, test, ejecución de acción, error de auth |
| Aislamiento | Un conector no puede leer configuración de otro; no hay endpoint de listado cross-org |

---

## 7. CICLO DE VIDA

```text
draft → registered → configured → verified → active ⇄ degraded
                                     ↘ failed
active/degraded → disabled → (deleted)
```

| Transición | Requisito |
| :--- | :--- |
| `registered → configured` | Config válida según `config_schema` + secretos completos |
| `configured → verified` | `test_connection` exitoso |
| `verified → active` | Habilitado por `admin` |
| `active → degraded` | Fallo de salud o circuit breaker |
| `degraded → active` | Éxito en `half_open` |
| `→ disabled` | Acción de `admin`, auditada; deja de ingerir/ejecutar |
| `→ deleted` | Solo si no hay acciones en curso; soft delete con histórico |

---

## 8. PRUEBAS DE CONTRATO (obligatorias por conector)

| Test | Qué verifica |
| :--- | :--- |
| `test_manifest_schema` | Manifiesto válido y capacidades del catálogo |
| `test_config_validation` | Rechazo de config inválida y de campos extra |
| `test_secret_not_exposed` | `GET` no devuelve secreto; logs redactados |
| `test_idempotent_push` | Mismo lote dos veces → sin duplicados |
| `test_error_mapping` | Cada error del vendor mapea a un `code` normalizado |
| `test_health_state` | Secuencia de fallos → `degraded` → `open` → recuperación |
| `test_action_idempotency` | `execute` dos veces con misma clave → un efecto |
| `test_verify_and_compensate` | Verificación detecta fallo; compensación revierte |
| `test_rate_limit` | Exceso → `429` local sin martillear el upstream |
| `test_no_ssrf` | Destino interno bloqueado salvo allowlist explícita |

---

## 9. CONECTORES DE REFERENCIA (release 1.0)

| Key | Kind | Capabilities | Transporte |
| :--- | :--- | :--- | :--- |
| `generic_syslog` | ingest | `events.read` | syslog UDP/TCP |
| `generic_webhook` | ingest | `events.read` | HTTPS push firmado |
| `hispanshield_edge` | ingest | `events.read` | HTTPS mTLS |
| `misp_feed` | ingest | `cti.read` | HTTPS pull |
| `taxii_feed` | ingest | `cti.read` | HTTPS pull |
| `aws_readonly` | ingest | `cloud.posture.read`, `assets.read`, `events.read` | HTTPS pull |
| `azure_readonly` | ingest | `cloud.posture.read`, `assets.read`, `events.read` | HTTPS pull |
| `gcp_readonly` | ingest | `cloud.posture.read`, `assets.read`, `events.read` | HTTPS pull |
| `generic_edr` | bidirectional | `events.read`, `host.isolate`, `file.quarantine`, `host.verify` | HTTPS |
| `generic_firewall` | bidirectional | `events.read`, `ip.block`, `ip.unblock` | HTTPS/API |
| `generic_idp` | bidirectional | `events.read`, `user.disable`, `user.enable` | HTTPS/API |
| `generic_ticketing` | action | `ticket.create` | HTTPS |

Un conector requiere: manifiesto, adaptador, mapeador OCSF (si ingesta), tests de contrato, entrada en `docs/connector-guide.md` y en la matriz de compatibilidad.

---

## 10. CRITERIOS DE ACEPTACIÓN

| AC | Criterio |
| :--- | :--- |
| `AC-104` | Manifiesto inválido rechazado; capacidades consultables |
| `AC-107` | Circuit breaker con backoff y estado visible |
| `AC-INT-01` | Ningún secreto expuesto en API/logs |
| `AC-INT-02` | Acción no declarada → `403 action_not_supported` |
| `AC-INT-03` | Tests de contrato verdes para cada conector de referencia |

## 11. EVIDENCIA

1. `pytest -q backend/tests/integration/test_connector_registry.py tests/integration/test_circuit_breaker.py`.
2. Manifiesto validado + respuesta `has_secret`.
3. Secuencia de health con estados y `next_attempt_at`.
4. Suite de contrato por conector de referencia.
