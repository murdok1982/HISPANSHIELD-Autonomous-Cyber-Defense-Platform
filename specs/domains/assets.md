# DOMINIO: ACTIVOS E INVENTARIO

- **Código:** `AST`
- **Ruta de implementación:** `backend/app/models/assets.py`, `backend/app/services/{assets,asset_graph,asset_import,zones,risk}.py`, `backend/app/api/v1/{assets,zones}.py`
- **Estado:** `SPECIFIED`
- **ACs globales:** `AC-15..AC-21`

---

## 1. OBJETIVO

Mantener un inventario único, fiable y contextualizado de todo lo que la organización debe proteger —hosts, redes, aplicaciones, recursos cloud, identidades, almacenes de datos, dispositivos IoT y activos OT— con criticidad de negocio, propietario, zona y relaciones, de modo que cualquier evento, vulnerabilidad o acción autónoma pueda evaluarse contra un activo real y su impacto.

## 2. CONTEXTO

El inventario es la columna vertebral de la plataforma: sin activo no hay scoring de riesgo, no hay blast radius y no hay política de autonomía defendible. Los datos llegan de tres vías: importación manual/CSV, importación de escáneres e integración de conectores (CMDB, cloud, EDR). La calidad del inventario es un requisito de seguridad, no un detalle administrativo.

El modelo soporta tres especializaciones que comparten tabla base: IoT (protocolo, firmware, zona), OT (Purdue, safety function, protocolos industriales) y cloud (ARN, cuenta, proveedor). La especialización se guarda en `attributes` con validación por esquema y restricciones en tabla.

## 3. REQUISITOS FUNCIONALES

| ID | Requisito | Detalle verificable |
| :--- | :--- | :--- |
| `REQ-AST-001` | Alta de activo | Campos obligatorios: `name`, `kind`, `criticality`, `owner` (email o user_id), `source`. `kind ∈ {host, network, application, cloud_resource, identity, data_store, iot, ot}`. UUIDv7. |
| `REQ-AST-002` | Criticidad | Entero 1..5; 5 = crítico NIS2. Cambio de criticidad requiere `admin` y justificación; se audita el valor anterior. |
| `REQ-AST-003` | Relaciones | Tipos: `depends_on`, `hosts`, `connects_to`, `protects`, `member_of`, `runs_on`, `trusts`. Detección de ciclos con DFS antes de insertar. |
| `REQ-AST-004` | Importación | CSV con cabecera declarada y JSON array; límite 10 MB / 10.000 filas; transacción por fila; respuesta `207` con errores por fila y campo. |
| `REQ-AST-005` | Búsqueda | FTS sobre `name`/`attributes` + filtros `kind`, `criticality_gte`, `zone_id`, `tag`, `owner`, `risk_score_gte`; cursor keyset; `limit ≤ 200`. |
| `REQ-AST-006` | Riesgo | `risk_score` 0..100 calculado desde vulnerabilidades abiertas (peso por severidad), exposición, criticidad y controles compensatorios; recalculado por evento de forma idempotente. |
| `REQ-AST-007` | Zonas | Zona = agrupación lógica con `name`, `kind` (`it|dmz|iot|ot|cloud`), `purdue_level?`, `description`. IoT/OT requieren zona. |
| `REQ-AST-008` | Ciclo de vida | `first_seen`, `last_seen`, `deleted_at`; soft delete con restore; purga solo por job y con auditoría. |
| `REQ-AST-009` | Etiquetas | `tags[]` normalizadas (minúsculas, `^[a-z0-9:_-]{1,40}$`), máximo 20; filtrables. |
| `REQ-AST-010` | Deduplicación | Si `attributes.ip` o `attributes.cloud_arn` coincide dentro de la org, el alta devuelve `409 duplicate_asset` con el `id` existente (salvo `force=true` auditado). |

## 4. REQUISITOS NO FUNCIONALES

| ID | Requisito |
| :--- | :--- |
| `NFR-AST-01` | Búsqueda p95 < 400 ms con 100k activos y 5 filtros combinados. |
| `NFR-AST-02` | Import de 10.000 filas ≤ 30 s, con memoria acotada (streaming). |
| `NFR-AST-03` | Recálculo de riesgo de 10k activos ≤ 60 s, idempotente y reanudable. |
| `NFR-AST-04` | Grafo de hasta 50k nodos y 200k aristas consultable sin bloquear escrituras. |

## 5. DEPENDENCIAS

| Dependencia | Tipo | Nota |
| :--- | :--- | :--- |
| `organizations` | Dominio | Tenancy |
| `vulnerabilities` | Dominio | Fuente de riesgo |
| `attack-surface` | Dominio | Exposición |
| `connectors` | Integración | Import desde CMDB/cloud/EDR |
| `core/events.py` | Interna | `asset.*` |

## 6. CONTRATOS

| Método | Endpoint | Rol | Entrada | Salida | Errores |
| :--- | :--- | :--- | :--- | :--- | :--- |
| GET | `/api/v1/assets` | `viewer`+ | `?q&kind&criticality_gte&zone_id&tag&cursor&limit` | `200 {data[],meta}` | `400,403` |
| POST | `/api/v1/assets` | `admin`+ | `AssetCreate` | `201 {asset}` | `403,409,422` |
| GET | `/api/v1/assets/{id}` | `viewer`+ | — | `200 {asset, relationships, vulns_summary, recent_events}` | `403,404` |
| PATCH | `/api/v1/assets/{id}` | `admin`+ | `AssetUpdate` | `200` | `403,404,409,422` |
| DELETE | `/api/v1/assets/{id}` | `admin`+ | — | `204` (soft) | `403,404,409` |
| POST | `/api/v1/assets/{id}/restore` | `admin`+ | — | `200` | `403,404,409` |
| POST | `/api/v1/assets/import` | `admin`+ | multipart | `207 {created,updated,failed[]}` | `413,415,422` |
| POST | `/api/v1/assets/{id}/relationships` | `admin`+ | `{target_id, type}` | `201` | `403,404,409,422` |
| DELETE | `/api/v1/assets/{id}/relationships/{rel_id}` | `admin`+ | — | `204` | `403,404` |
| GET | `/api/v1/assets/{id}/graph?depth=2` | `viewer`+ | — | `200 {nodes[],edges[]}` | `403,404` |
| GET/POST/PATCH/DELETE | `/api/v1/zones` | `admin`+ | `ZoneCreate` | `200/201/204` | `403,409,422` |

**Esquema `AssetCreate`:**
```json
{
  "name": "plc-subestacion-01",
  "kind": "ot",
  "criticality": 5,
  "owner": "ot@example.eu",
  "zone_id": "0192f0c4-...",
  "tags": ["energia", "nivel1"],
  "attributes": {
    "ip": "10.20.0.11",
    "vendor": "Siemens",
    "model": "S7-1500",
    "protocols": ["s7comm", "modbus"],
    "purdue_level": 1,
    "safety_function": true
  },
  "source": "import"
}
```

## 7. CASOS DE USO

1. **Onboarding de inventario:** el integrador importa un CSV de 3.000 hosts; 47 filas fallan por criticidad inválida; recibe el informe, corrige y reimporta solo las fallidas.
2. **Contexto de incidente:** un analista abre un incidente y salta al activo; ve sus vulnerabilidades abiertas, exposición y últimos eventos.
3. **Cambio de criticidad:** tras una auditoría, el `admin` sube a 5 un servidor de base de datos; el sistema recalcula su riesgo y las vulnerabilidades P0 asociadas.
4. **Aislamiento:** el `responder` solicita aislar un host; la política evalúa el activo, su criticidad y si es OT con safety function.
5. **Inventario OT:** el responsable de planta crea la zona `subestacion-a` con Purdue 1 y asigna 12 PLCs con `safety_function`.

## 8. CASOS BORDE

| Escenario | Comportamiento |
| :--- | :--- |
| `criticality=0` o `6` | `422 validation_error`, campo `criticality` |
| `kind=iot` sin `zone_id` | `422`, campo `zone_id`, mensaje "requerido para activos IoT/OT" |
| `kind=ot` sin `purdue_level` | `422`, campo `attributes.purdue_level` |
| Ciclo A→B→A | `409 relationship_cycle` con la ruta detectada |
| Auto-relación A→A | `422 self_relationship` |
| Relación duplicada | `409 relationship_exists` (idempotente por tipo+destino) |
| Import con cabecera desconocida | `422 missing_columns` listando requeridas |
| Import con 0 filas válidas | `207` con `created=0` y `failed[]` completo (no `400`) |
| IP malformada en `attributes.ip` | `422` con `path=attributes.ip` |
| Duplicado por IP | `409 duplicate_asset` con `existing_id` |
| Restore de activo cuya zona fue borrada | `409 zone_missing` con acción sugerida |
| Borrado con incidentes abiertos | Permitido (soft) pero devuelve `warnings[]` con IDs |
| Búsqueda con `limit=5000` | `422 limit_exceeded` (máx 200) |

## 9. AMENAZAS ESPECÍFICAS

| Amenaza | Vector | Control |
| :--- | :--- | :--- |
| Inventario envenenado | Import con activos falsos para desviar política | Import requiere `admin`, se marca `source`, se audita; los activos importados no elevan autonomía por sí solos |
| Fuga de topología | Export o API sin scope | Scoping por org, permisos, export auditado |
| DoS por import masivo | CSV gigante o filas complejas | Límite de tamaño/filas, streaming, timeout por fila |
| Manipulación de criticidad | Bajar criticidad para evitar SLA/autonomía | Cambio auditado y limitado a `admin`; alerta si se baja un activo 5→1 |
| Borrado accidental | `DELETE` masivo | Soft delete, restore, confirmación en UI, auditoría |

## 10. CRITERIOS DE ACEPTACIÓN

| AC | Criterio | Test |
| :--- | :--- | :--- |
| `AC-15` | Alta válida con riesgo inicial; criticidad inválida rechazada | `backend/tests/integration/test_assets_crud.py::test_create_and_validate` |
| `AC-16` | Ciclo rechazado | `backend/tests/unit/test_asset_graph.py::test_cycle_rejected` |
| `AC-17` | Import parcial con informe | `backend/tests/integration/test_asset_import.py::test_partial_import_report` |
| `AC-18` | Soft delete + restore | `backend/tests/integration/test_assets_crud.py::test_soft_delete_restore` |
| `AC-19` | Búsqueda cursor p95 | `backend/tests/performance/test_assets_search.py` |
| `AC-20` | Validación IoT/OT | `backend/tests/integration/test_assets_iot_validation.py` |
| `AC-21` | Recomputación idempotente | `backend/tests/integration/test_risk_recompute.py::test_idempotent_recompute` |
| `AC-AST-08` | Duplicado por IP/ARN | `backend/tests/integration/test_asset_dedupe.py` |

## 11. ESTRATEGIA DE TEST

- **Unit:** validación de `kind`/`attributes` por tipo, ciclos, normalización de tags, fórmula de riesgo.
- **Integración:** CRUD, import, restore, relaciones, zonas, dedupe, eventos de outbox.
- **Rendimiento:** 100k activos, consultas combinadas, import 10k.
- **E2E:** pantalla `/assets` con tabla, grafo, drawer y empty state.
- **Seguridad:** aislamiento, mass assignment (`organization_id` en body debe ignorarse), límites.

## 12. EVIDENCIA REQUERIDA

1. `pytest -q tests/integration/test_assets_*.py tests/unit/test_asset_graph.py`.
2. Informe de import con filas fallidas (JSON real).
3. Bench de búsqueda con p95 y plan de ejecución (`EXPLAIN (ANALYZE, BUFFERS)`).
4. Salida de `test_risk_recompute` con dos ejecuciones y hash de resultado idéntico.
5. Captura de `/assets` con estados loading/empty/error.
