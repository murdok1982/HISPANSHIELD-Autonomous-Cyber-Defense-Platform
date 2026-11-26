# DOMINIO: THREAT INTELLIGENCE

- **Código:** `CTI`
- **Ruta de implementación:** `backend/app/models/threat_intel.py`, `backend/app/services/{threat_intel,ioc_matching}.py`, `backend/app/integrations/{stix,taxii_client,misp_client}.py`
- **Estado:** `SPECIFIED`
- **ACs globales:** `AC-50..AC-54`

---

## 1. OBJETIVO

Ingerir, normalizar y correlacionar inteligencia de amenazas (indicadores, actores, campañas, malware, TTPs) con la telemetría y el inventario propios, para convertir contexto externo en detecciones accionables y priorización informada, sin generar ruido ni alertas sobre indicadores caducados o en whitelist.

## 2. CONTEXTO

Los organismos reciben inteligencia de CERTs nacionales, MISP comunitarios, proveedores y feeds TAXII. El formato dominante es STIX 2.1; el transporte, TAXII 2.1 o descarga. La calidad varía: indicadores sin TTL, con confianza baja, duplicados o ya obsoletos. Este dominio aplica TTL, decay de confianza, dedupe y whitelist antes de alertar.

La correlación se hace contra eventos normalizados y activos, no contra texto libre. Cada match produce evidencia trazable al `event_id` o `asset_id` y al indicador que lo originó.

## 3. REQUISITOS FUNCIONALES

| ID | Requisito | Detalle verificable |
| :--- | :--- | :--- |
| `REQ-CTI-001` | Indicador | `{type(ipv4-addr,domain-name,url,file-hash,email), value_normalized, pattern, confidence 0..100, tlp, valid_from, valid_until, labels[], source_feed, stix_id}`. |
| `REQ-CTI-002` | Entidades | `threat_actor`, `campaign`, `malware`, `tool`, `infrastructure` con `stix_id`, aliases y relaciones (`uses`, `attributed-to`, `targets`, `indicates`). |
| `REQ-CTI-003` | STIX | Import de bundle 2.1 (objetos soportados); export de bundle con `x_hispanshield_*` para metadatos locales; round-trip sin pérdida de campos clave. |
| `REQ-CTI-004` | TAXII | Cliente 2.1 con `collection_id`, `added_after` incremental, paginación `next`, backoff, métricas por ejecución. |
| `REQ-CTI-005` | MISP | Búsqueda por `last`/`timestamp`, `to_ids`, tags; normalización a indicadores; atributos compuestos soportados (ip|port). |
| `REQ-CTI-006` | TTL/decay | Al pasar `valid_until` → `expired`, sin matching. Confianza efectiva = `confidence * exp(-λ * age_days)` con λ configurable; bajo umbral → solo contexto. |
| `REQ-CTI-007` | Matching | Contra `events` (src/dst ip, domain, url, hash) y `assets` (ip, domain); ventana de evaluación; resultado `indicator_match` con `confidence_effective`. |
| `REQ-CTI-008` | Whitelist | `ioc_whitelist{org, value, reason, expires_at}`; match en whitelist no alerta y se registra `suppressed_whitelist`. |
| `REQ-CTI-009` | Salud de feed | Estado `healthy/degraded/failed`, `last_success_at`, `last_error`, contadores; visible en API/UI. |
| `REQ-CTI-010` | Dedupe | Clave `(org, type, value_normalized)`; actualiza confianza/TTL y `sources[]` en lugar de duplicar. |

## 4. REQUISITOS NO FUNCIONALES

| ID | Requisito |
| :--- | :--- |
| `NFR-CTI-01` | Import STIX de 50.000 objetos ≤ 120 s. |
| `NFR-CTI-02` | Matching de 10.000 indicadores contra 1M eventos ≤ 5 min por ciclo incremental. |
| `NFR-CTI-03` | Sincronización TAXII tolerante a fallos: no pierde el cursor `added_after` en error. |
| `NFR-CTI-04` | Índice de búsqueda exacta por valor normalizado (hash/ip/domain) para matching O(log n). |

## 5. DEPENDENCIAS

| Dependencia | Tipo | Nota |
| :--- | :--- | :--- |
| `siem` | Dominio | Eventos para matching |
| `assets` | Dominio | Inventario para matching |
| `incidents` | Dominio | Enriquecimiento y promoción |
| `connectors` | Integración | Credenciales y salud |
| `httpx` anti-SSRF | Interna | Acceso a feeds |

## 6. CONTRATOS

| Método | Endpoint | Rol | Entrada | Salida |
| :--- | :--- | :--- | :--- | :--- |
| GET/POST | `/api/v1/threat-intel/indicators` | `analyst`+ | `IndicatorCreate` | `200/201` |
| GET | `/api/v1/threat-intel/indicators/{id}` | `analyst`+ | — | `200 {indicator, matches[], actor?}` |
| GET/POST | `/api/v1/threat-intel/actors` · `/campaigns` | `analyst`+ | `ActorCreate` | `200/201` |
| POST | `/api/v1/threat-intel/stix/import` | `analyst`+ | bundle | `207 {created,updated,skipped,errors[]}` |
| GET | `/api/v1/threat-intel/stix/export` | `analyst`+ | filtros | `200` bundle |
| GET/POST | `/api/v1/threat-intel/feeds` | `admin`+ | `FeedCreate` | `200/201` |
| POST | `/api/v1/threat-intel/feeds/{id}/sync` | `admin`+ | `{full?}` | `202 {run_id}` |
| GET | `/api/v1/threat-intel/feeds/{id}/runs` | `admin`+ | — | `200 [{state, stats, error}]` |
| GET/POST/DELETE | `/api/v1/threat-intel/whitelist` | `admin`+ | `{value, reason, expires_at}` | `200/201/204` |
| GET | `/api/v1/threat-intel/matches` | `analyst`+ | `?since&indicator_id` | `200` |

**Indicador (ejemplo):**
```json
{
  "type": "ipv4-addr",
  "value": "203.0.113.77",
  "pattern": "[ipv4-addr:value = '203.0.113.77']",
  "confidence": 85,
  "tlp": "amber",
  "valid_from": "2026-11-20T00:00:00Z",
  "valid_until": "2027-02-20T00:00:00Z",
  "labels": ["c2", "apt-x"],
  "source_feed": "cert-eu-daily",
  "stix_id": "indicator--0f1e..."
}
```

## 7. CASOS DE USO

1. **Feed CERT diario:** sincronización incremental; 1.200 indicadores nuevos, 300 actualizados, 12 errores de formato reportados.
2. **Match en tráfico:** una IP de C2 aparece como `dst_ip` en eventos del firewall; se crea alerta con confianza efectiva 72 y evidencia del evento.
3. **Whitelist:** el rango del proveedor de backup coincide con un IOC de baja calidad; se añade a whitelist con motivo y caducidad; deja de alertar.
4. **Enriquecimiento de incidente:** un incidente muestra el actor y campaña asociados al IOC que lo disparó.
5. **Caducidad:** un indicador de 2024 con `valid_until` vencido deja de generar matches y se marca `expired`.

## 8. CASOS BORDE

| Escenario | Comportamiento |
| :--- | :--- |
| STIX con objeto no soportado | Se omite con `skipped` y motivo; el resto se importa |
| STIX con relación a objeto ausente | Se crea placeholder `unresolved` y se reporta |
| `valid_until < valid_from` | `422 invalid_validity_window` |
| IP inválida para tipo `ipv4-addr` | `422 invalid_indicator_value` |
| Indicador duplicado con distinta confianza | Prevalece la mayor; `sources[]` acumula |
| Feed devuelve 429 | Backoff y reintento; estado `degraded` |
| Feed devuelve STIX malformado | `failed` con `parse_error`, cursor no avanza |
| Whitelist con `expires_at` pasado | `422`; la existente caducada se ignora |
| Match sobre evento ya borrado por retención | No se evalúa; se documenta ventana |
| Confianza efectiva < umbral | Se registra `match_low_confidence`, no alerta |
| Bundle > 50 MB | `413 payload_too_large` |

## 9. AMENAZAS ESPECÍFICAS

| Amenaza | Vector | Control |
| :--- | :--- | :--- |
| Envenenamiento de inteligencia | Feed comprometido con IOCs de infraestructura propia | Whitelist, confianza mínima, revisión de feeds, TLP |
| SSRF vía feed | URL de feed apuntando a red interna | Cliente anti-SSRF + allowlist de esquemas |
| Exfiltración en export | Export STIX con datos internos | `x_hispanshield_*` limitado; permisos y auditoría |
| Fatiga de alertas | Miles de IOCs de baja calidad | Decay, umbral, dedupe, agrupación por actor |
| Suplantación de feed | HTTP sin TLS | Solo HTTPS, verificación de certificado, pinning opcional |

## 10. CRITERIOS DE ACEPTACIÓN

| AC | Criterio | Test |
| :--- | :--- | :--- |
| `AC-50` | STIX import/export round-trip | `backend/tests/integration/test_stix_roundtrip.py` |
| `AC-51` | TAXII paginado e incremental | `backend/tests/integration/test_taxii_client.py` |
| `AC-52` | TTL expira y no alerta | `backend/tests/unit/test_indicator_ttl.py` |
| `AC-53` | Matching con whitelist | `backend/tests/integration/test_ioc_matching.py` |
| `AC-54` | Feed caído → degradado visible | `backend/tests/integration/test_feed_health.py` |
| `AC-CTI-08` | Dedupe y acumulación de fuentes | `backend/tests/integration/test_indicator_dedupe.py` |

## 11. ESTRATEGIA DE TEST

- **Unit:** normalización de valores, TTL/decay, parseo STIX, whitelist.
- **Integración:** import/export, TAXII con servidor de prueba local, MISP simulado por fixture HTTP, matching end-to-end, salud de feed.
- **Seguridad:** SSRF, tamaño, aislamiento, export.
- **E2E:** `/threat-intel` con feeds degradados.

## 12. EVIDENCIA REQUERIDA

1. `pytest -q tests/integration/test_stix_roundtrip.py tests/integration/test_ioc_matching.py tests/integration/test_feed_health.py`.
2. Bundle STIX de entrada/salida con conteo y diff de IDs.
3. Ejemplo de alerta por match con `confidence_effective` y `event_id`.
4. Log de feed `degraded` con `last_error` y `next_attempt_at`.
5. Prueba de whitelist suprimiendo un match.
