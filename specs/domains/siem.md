# DOMINIO: SIEM (EVENTOS, DETECCIÓN Y ALERTAS)

- **Código:** `SIEM`
- **Ruta de implementación:** `backend/app/integrations/ocsf/`, `backend/app/detection/`, `backend/app/services/{ingest,event_search,detection_rules,alerts}.py`, `backend/app/workers/{syslog_listener,detection,retention}.py`
- **Estado:** `SPECIFIED`
- **ACs globales:** `AC-33..AC-42`

---

## 1. OBJETIVO

Recibir telemetría heterogénea, normalizarla a un esquema común (OCSF), almacenarla de forma inmutable y consultable, evaluarla con reglas versionadas y producir alertas priorizadas y deduplicadas que alimenten la respuesta.

## 2. CONTEXTO

Las fuentes típicas son firewall, proxy, DNS, EDR, Active Directory, servidores Linux/Windows, cloud audit logs y dispositivos OT. Cada una habla un dialecto. Sin normalización, cada regla necesita un parser distinto y la búsqueda es imposible. OCSF aporta un esquema vendor-neutral; aquí se implementa un subconjunto estable y extensible.

El volumen y la retención son el principal coste. La estrategia es: ingesta por lotes, particiones mensuales, índices GIN para FTS, retención por clase de dato y consultas acotadas. No hay OpenSearch: PostgreSQL es suficiente hasta el límite documentado y la interfaz de repositorio permite migrar.

## 3. REQUISITOS FUNCIONALES

### 3.1 Ingesta y normalización

| ID | Requisito | Detalle verificable |
| :--- | :--- | :--- |
| `REQ-SIEM-001` | Syslog | UDP y TCP en `:5514`; RFC 5424 y 3164; extracción de `pri`, `timestamp`, `hostname`, `app-name`, `procid`, `msg`; límite 64 KB por mensaje; descarte auditado si excede. |
| `REQ-SIEM-002` | Webhook | `POST /events/webhook/{connector_id}` con `X-HS-Signature: sha256=<hmac>` sobre el cuerpo crudo; ventana anti-replay ±300 s con `X-HS-Timestamp`; `Idempotency-Key` opcional; lote ≤500 eventos. |
| `REQ-SIEM-003` | OCSF | Mapeo a `class_uid`, `activity_id`, `severity_id`, `time`, `metadata{version,product,uid,original_time}`, `actor`, `device`, `src_endpoint`, `dst_endpoint`, `observables[]`, `raw`. |
| `REQ-SIEM-004` | Inmutabilidad | `raw` y fila completa append-only; trigger bloquea `UPDATE`/`DELETE`; retención por `DROP PARTITION`. `raw_hash` SHA-256. |
| `REQ-SIEM-005` | Idempotencia | `event_uid` único por `(organization_id, event_uid)`; duplicados devuelven `202` con `duplicates>0`. |
| `REQ-SIEM-006` | Backpressure | Cola acotada; si se supera, `503 ingest_backpressure` con `retry_after` y métrica `ingest_queue_depth`; nunca pérdida silenciosa de eventos aceptados. |

### 3.2 Búsqueda

| ID | Requisito | Detalle verificable |
| :--- | :--- | :--- |
| `REQ-SIEM-007` | Búsqueda | `POST /events/search` con filtros tipados: `time_range` (máx 90 d sin filtro adicional), `class_uid`, `severity_gte`, `src_ip`, `dst_ip`, `actor`, `q` (FTS), `observable`. |
| `REQ-SIEM-008` | Guard de consulta | Rango >90 d sin filtro, o `limit>1000`, o patrón FTS demasiado amplio → `422 query_too_broad` con sugerencia. |
| `REQ-SIEM-009` | Resultados | Proyección limitada (≤40 campos), `meta.total_estimate` etiquetado como estimación, `took_ms`. |

### 3.3 Detección

| ID | Requisito | Detalle verificable |
| :--- | :--- | :--- |
| `REQ-SIEM-010` | DSL | Gramática: `field op value [AND|OR ...] [| window 5m] [| group_by field] [| threshold > N]`. Campos y operadores allowlisted. Parser produce AST serializable. |
| `REQ-SIEM-011` | Versionado | Regla con `versions[]` inmutables; `draft/active/disabled`; publicar crea versión y activa; nunca se edita una versión publicada. |
| `REQ-SIEM-012` | Test | `POST /detection-rules/{id}/test` con ventana y filtros; devuelve eventos coincidentes (máx 100) y conteo, sin crear alertas. |
| `REQ-SIEM-013` | Evaluación | Ventanas tumbling/hopping configurables; estado por `(rule_version, group_key)`; umbral; supresión si alerta `open` con mismo `dedupe_key`. |
| `REQ-SIEM-014` | Dedupe | `dedupe_key = sha256(rule_id|group_key|window_bucket)`; una alerta por clave y ventana; actualiza `last_seen`/`count`. |
| `REQ-SIEM-015` | Correlación | Regla de correlación agrupa ≥N alertas por `actor`/`asset`/`src_ip` en ventana → incidente con `alert_ids[]`. |

### 3.4 Alertas

| ID | Requisito | Detalle verificable |
| :--- | :--- | :--- |
| `REQ-SIEM-016` | Ciclo de vida | `open → acknowledged → resolved`; `suppressed` con `reason ≥20` y `until ≤30 d`; reapertura si vuelve a dispararse tras `resolved`. |
| `REQ-SIEM-017` | Priorización | `severity` de la regla ajustada por criticidad del activo y confianza; `priority_score` 0..100 explicable. |
| `REQ-SIEM-018` | Promoción | `POST /alerts/{id}/promote` crea incidente (o vincula a existente) con timeline y evidencia de eventos. |

## 4. REQUISITOS NO FUNCIONALES

| ID | Requisito |
| :--- | :--- |
| `NFR-SIEM-01` | Ingesta sostenida ≥2.000 ev/s single-node con lotes de 500. |
| `NFR-SIEM-02` | Latencia evento→búsqueda ≤2 s p95; evento→alerta ≤10 s p95. |
| `NFR-SIEM-03` | Búsqueda p95 <500 ms a 1M eventos. |
| `NFR-SIEM-04` | 0 pérdidas de eventos con `202`. |
| `NFR-SIEM-05` | Evaluación de 500 reglas activas sin superar 1 core por cada 500 ev/s. |

## 5. DEPENDENCIAS

| Dependencia | Tipo | Nota |
| :--- | :--- | :--- |
| `assets` | Dominio | Enriquecimiento y prioridad |
| `threat-intelligence` | Dominio | Matching IOC |
| `incidents` | Dominio | Promoción/correlación |
| `connectors` | Integración | Autenticación de webhook, salud |
| `edge` | Integración | Ingesta store-and-forward |
| `workflow` | Plataforma | Job de evaluación y retención |

## 6. CONTRATOS

| Método | Endpoint | Rol | Entrada | Salida |
| :--- | :--- | :--- | :--- | :--- |
| POST | `/api/v1/events/webhook/{connector_id}` | HMAC | `RawEventBatch` | `202 {accepted, duplicates, event_ids[]}` |
| POST | `/api/v1/edge/ingest` | mTLS+HMAC | lote con `sequence` | `202 {accepted, highest_sequence}` |
| POST | `/api/v1/events/search` | `analyst`+ | `EventQuery` | `200 {data[],meta,took_ms}` |
| GET | `/api/v1/events/stream` | `analyst`+ | filtros | `text/event-stream` |
| GET/POST | `/api/v1/detection-rules` | `analyst`+ | `RuleCreate` | `200/201` |
| POST | `/api/v1/detection-rules/{id}/versions` | `admin`+ | `{dsl, severity, description}` | `201 {version}` |
| POST | `/api/v1/detection-rules/{id}/publish` | `admin`+ | `{version}` | `200` |
| POST | `/api/v1/detection-rules/{id}/test` | `analyst`+ | `{from,to,filters}` | `200 {matched,count,sample[]}` |
| GET | `/api/v1/alerts` | `analyst`+ | `?status&severity&assignee&cursor` | `200` |
| PATCH | `/api/v1/alerts/{id}` | `analyst`+ | `{status, reason?, assignee?}` | `200` |
| POST | `/api/v1/alerts/{id}/promote` | `responder`+ | `{incident_id?}` | `201 {incident}` |

**Evento OCSF mínimo (ejemplo):**
```json
{
  "class_uid": 3002,
  "activity_id": 1,
  "severity_id": 4,
  "time": "2026-11-26T08:14:03.221Z",
  "metadata": {"version": "1.3.0", "product": {"name": "fortigate", "vendor_name": "Fortinet"}, "uid": "fg-88213"},
  "actor": {"user": {"name": "jdoe", "type": "User"}},
  "src_endpoint": {"ip": "198.51.100.23", "port": 51544},
  "dst_endpoint": {"ip": "10.10.4.12", "port": 3389},
  "observables": [{"name": "src_endpoint.ip", "type": "IP Address", "value": "198.51.100.23"}],
  "status": "Failure",
  "raw": "<134>1 2026-11-26T08:14:03Z fw01 fortigate - - - action=deny src=198.51.100.23 dst=10.10.4.12 dport=3389",
  "raw_hash": "b1e4..."
}
```

## 7. CASOS DE USO

1. **Firewall a syslog:** se configura el envío a `:5514/udp`; en 2 s el evento es visible y buscable por IP.
2. **EDR por webhook:** el conector firma el lote; la regla `ransomware_behavior` dispara y crea alerta P1 vinculada al activo.
3. **Regla de fuerza bruta:** 12 fallos del mismo `src_ip` en 5 min → 1 alerta deduplicada, no 12.
4. **Investigación:** el analista busca `actor.user.name=jdoe AND severity>=3` en 7 días; exporta 200 eventos a CSV.
5. **Correlación:** 4 alertas del mismo host en 10 min → incidente P2 con todas vinculadas.
6. **Supresión justificada:** una regla de escaneo interno genera ruido; se suprime 7 días con motivo y ticket.

## 8. CASOS BORDE

| Escenario | Comportamiento |
| :--- | :--- |
| Syslog no parseable | Se conserva crudo, `class_uid=0` (`Unknown`), contador `unparsed` y log; no se pierde |
| Mensaje >64 KB | `discarded_oversize`, métrica incrementada |
| Webhook con firma válida pero cuerpo >10 MB | `413 payload_too_large`, sin procesar |
| Firma correcta con timestamp viejo | `401 signature_expired` |
| Duplicado exacto en lote | Se cuenta una vez, `duplicates` refleja el resto |
| Regla con campo inexistente | `422 unknown_field` en validación, no en runtime |
| Regla que casa 1M eventos en test | `422 test_too_broad`, acotar ventana |
| Alerta suprimida y luego reaparece | Nueva alerta con `suppression_ended` en timeline |
| Query con `limit=10000` | `422 limit_exceeded` |
| BD llena durante ingesta | `503 storage_pressure` con `retry_after`; no se aceptan eventos que no se puedan persistir |
| Reinicio del worker de detección | Reanuda desde `last_window_end` persistido; sin hueco >1 ventana |
| Evento con `time` futuro >5 min | Se acepta pero se marca `clock_skew=true` y se alerta |

## 9. AMENAZAS ESPECÍFICAS

| Amenaza | Vector | Control |
| :--- | :--- | :--- |
| Inyección de eventos | Webhook sin firma o replay | HMAC, timestamp, idempotencia, allowlist de conector |
| Supresión de evidencia | `UPDATE`/`DELETE` de eventos | Trigger append-only, permisos de BD restringidos |
| DoS por ingesta | Flood de syslog/webhook | Rate limit por conector, cola acotada, backpressure |
| Evasión de detección | Reglas con campos mal mapeados | Validación de DSL, test contra muestras, cobertura de campos OCSF |
| Fuga cross-org en búsqueda | Filtro sin scope | Repositorio con `organization_id` obligatorio + test |
| Query costosa | Rango enorme o FTS amplio | Guard `query_too_broad`, límites, timeouts |

## 10. CRITERIOS DE ACEPTACIÓN

| AC | Criterio | Test |
| :--- | :--- | :--- |
| `AC-33` | Syslog RFC 5424 → OCSF en ≤2 s | `backend/tests/integration/test_syslog_ingest.py::test_rfc5424_udp_normalized` |
| `AC-34` | Firma HMAC obligatoria | `backend/tests/security/test_webhook_hmac.py` |
| `AC-35` | Idempotencia | `backend/tests/integration/test_event_idempotency.py` |
| `AC-36` | DSL inválido rechazado | `backend/tests/unit/test_rule_dsl.py::test_invalid_rule_rejected` |
| `AC-37` | Umbral y dedupe | `backend/tests/integration/test_detection_engine.py::test_threshold_and_dedupe` |
| `AC-38` | Supresión con motivo | `backend/tests/integration/test_alert_lifecycle.py` |
| `AC-39` | Búsqueda p95 | `backend/tests/performance/test_event_search.py` |
| `AC-40` | Correlación a incidente | `backend/tests/integration/test_correlation_to_incident.py` |
| `AC-41` | Inmutabilidad | `backend/tests/security/test_event_immutability.py` |
| `AC-42` | Retención por partición | `backend/tests/integration/test_retention_job.py` |

## 11. ESTRATEGIA DE TEST

- **Unit:** parser DSL, mapeo OCSF por fuente, ventanas, dedupe key, prioridad.
- **Integración:** syslog real por socket, webhook firmado, búsqueda, detección end-to-end, retención.
- **Rendimiento:** 2.000 ev/s durante 10 min; 1M eventos para búsqueda.
- **Seguridad:** inmutabilidad, HMAC, replay, aislamiento, límites.
- **E2E:** `/siem` y `/threats/live`.

## 12. EVIDENCIA REQUERIDA

1. `pytest -q tests/integration/test_syslog_ingest.py tests/integration/test_detection_engine.py tests/security/test_webhook_hmac.py`.
2. Bench de ingesta con ev/s y latencia p95.
3. `EXPLAIN (ANALYZE)` de búsqueda FTS a 1M eventos.
4. Ejemplo de alerta deduplicada con `dedupe_key` y `count`.
5. Salida del job de retención con particiones eliminadas.
