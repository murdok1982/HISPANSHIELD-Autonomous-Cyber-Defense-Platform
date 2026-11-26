# DOMINIO: FORENSE DIGITAL

- **Código:** `FOR`
- **Ruta de implementación:** `backend/app/models/forensics.py`, `backend/app/services/{forensics,forensic_timeline}.py`, `backend/app/api/v1/forensics.py`
- **Estado:** `SPECIFIED`
- **ACs globales:** `AC-59` (+ `AC-FOR-*`)

---

## 1. OBJETIVO

Preservar y reconstruir la evidencia de un incidente con integridad demostrable y cadena de custodia, de modo que sirva tanto para la respuesta técnica como para un procedimiento disciplinario, regulatorio o judicial.

## 2. CONTEXTO

La plataforma no adquiere memoria ni disco de endpoints (fuera de alcance). Lo que sí hace: recibir artefactos exportados por herramientas del cliente, calcular y almacenar su hash, registrar quién accedió y cuándo, reconstruir una línea temporal a partir de eventos y acciones, y exportar un paquete verificable. El `legal_hold` impide que la retención automática destruya evidencia.

## 3. REQUISITOS FUNCIONALES

| ID | Requisito | Detalle verificable |
| :--- | :--- | :--- |
| `REQ-FOR-001` | Caso | `case{id, org, ref, title, incident_id?, state(open,closed,archived), legal_hold, opened_by, opened_at, closed_at}`. |
| `REQ-FOR-002` | Evidencia | `evidence{id, case_id, filename, mime, size, sha256, uploaded_by, collected_at, source, description, storage_path}`; ≤50 MB; MIME por magic bytes; ruta `{org}/{case}/{uuid}` con permisos 0600. |
| `REQ-FOR-003` | Custodia | `custody_entry{evidence_id, action(upload,view,download,verify,export), actor, at, ip, request_id, hash_at_action}`; append-only. |
| `REQ-FOR-004` | Verificación | `POST /forensics/evidence/{id}/verify` recalcula SHA-256; discrepancia → `409 evidence_integrity_failed` + cuarentena + alerta. |
| `REQ-FOR-005` | Timeline | Reconstrucción desde `events` (ventana), `incident_timeline`, `actions` y `custody_entry`, ordenada y deduplicada, con `source` por entrada. |
| `REQ-FOR-006` | Export | Paquete ZIP con evidencias, `manifest.json` (sha256 por fichero + hash del manifiesto) y `timeline.json`; descarga auditada. |
| `REQ-FOR-007` | Legal hold | Bloquea borrado/purga del caso y sus evidencias; solo `owner` o `auditor` puede levantarlo, con motivo. |
| `REQ-FOR-008` | Acceso | Solo `responder+` y `auditor`; toda lectura/descarga se audita; `viewer` no ve contenido ni nombres. |

## 4. REQUISITOS NO FUNCIONALES

| ID | Requisito |
| :--- | :--- |
| `NFR-FOR-01` | Hash SHA-256 de 50 MB ≤2 s. |
| `NFR-FOR-02` | Export de caso con 100 evidencias ≤5 min con streaming (sin cargar todo en memoria). |
| `NFR-FOR-03` | Timeline de 100k entradas paginada ≤2 s. |
| `NFR-FOR-04` | Verificación de integridad programada diaria con informe. |

## 5. DEPENDENCIAS

| Dependencia | Tipo | Nota |
| :--- | :--- | :--- |
| `incidents` | Dominio | Vinculación |
| `siem` | Dominio | Timeline |
| `autonomy`/`soar` | Dominio | Acciones ejecutadas |
| `core/audit.py` | Interna | Custodia |
| Storage | Plataforma | Volumen con permisos |

## 6. CONTRATOS

| Método | Endpoint | Rol | Entrada | Salida |
| :--- | :--- | :--- | :--- | :--- |
| GET/POST | `/api/v1/forensics/cases` | `responder`+ | `CaseCreate` | `200/201` |
| GET/PATCH | `/api/v1/forensics/cases/{id}` | `responder`+ | `CaseUpdate` | `200` |
| POST | `/api/v1/forensics/cases/{id}/evidence` | `responder`+ | multipart | `201 {evidence, sha256}` |
| GET | `/api/v1/forensics/evidence/{id}` | `responder`+ | — | binario + `X-Content-SHA256` |
| POST | `/api/v1/forensics/evidence/{id}/verify` | `analyst`+ | — | `200 {valid, sha256}` / `409` |
| GET | `/api/v1/forensics/cases/{id}/timeline` | `responder`+ | `?from&to` | `200 {entries[]}` |
| POST | `/api/v1/forensics/cases/{id}/export` | `responder`+ | — | `202 {export_id}` |
| GET | `/api/v1/forensics/exports/{id}` | `responder`+ | — | `200` ZIP |
| POST | `/api/v1/forensics/cases/{id}/legal-hold` | `owner`/`auditor` | `{active, reason}` | `200` |

## 7. CASOS DE USO

1. **Apertura de caso:** tras un incidente P1, el `responder` abre caso, vincula incidente y activa legal hold.
2. **Carga de artefactos:** sube un volcado de logs y una captura de memoria exportada por el EDR del cliente; se calculan hashes.
3. **Verificación:** a los 30 días se verifica integridad; todo correcto; se registra custodia.
4. **Export para auditoría:** se genera ZIP con manifiesto; el auditor verifica el hash del manifiesto y de cada fichero.
5. **Intento de purga:** el job de retención detecta legal hold y omite, registrando `skipped_legal_hold`.

## 8. CASOS BORDE

| Escenario | Comportamiento |
| :--- | :--- |
| Fichero >50 MB | `413 payload_too_large` |
| MIME declarado distinto del real | `415 unsupported_media_type` |
| Evidencia alterada | `409 evidence_integrity_failed`, `quarantined=true` |
| Descarga por `viewer` | `403` + auditoría de intento |
| Borrar caso con legal hold | `409 legal_hold_active` |
| Levantar hold sin motivo | `422 reason_required` |
| Export sin evidencias | `200` ZIP con manifiesto vacío válido |
| Caso cerrado y nueva evidencia | `409 case_closed` (reapertura explícita) |
| Timeline con hueco de retención | Se marca `gap` con rango faltante, no se inventa |
| Export interrumpido | Job reanudable; no deja ZIP parcial descargable |

## 9. AMENAZAS ESPECÍFICAS

| Amenaza | Vector | Control |
| :--- | :--- | :--- |
| Destrucción de evidencia | Purga o borrado | Legal hold, append-only, auditoría |
| Manipulación | Sustitución de fichero | SHA-256 + verificación + cuarentena |
| Fuga de evidencia | Descarga no autorizada | RBAC, auditoría, nombres UUID, sin listado a `viewer` |
| Repudio | "Yo no descargué eso" | Custodia con actor, IP, `request_id` |
| ZIP bomb en export | Datos manipulados | Solo ficheros subidos validados; límites de tamaño |

## 10. CRITERIOS DE ACEPTACIÓN

| AC | Criterio | Test |
| :--- | :--- | :--- |
| `AC-59` | Legal hold bloquea purga | `backend/tests/integration/test_legal_hold.py` |
| `AC-58` | Acceso restringido y auditado | `backend/tests/security/test_evidence_access.py` |
| `AC-57` | Hash e integridad | `backend/tests/security/test_evidence_integrity.py` |
| `AC-FOR-02` | Export con manifiesto verificable | `backend/tests/integration/test_forensic_export.py` |
| `AC-FOR-03` | Timeline con fuentes y gaps | `backend/tests/integration/test_forensic_timeline.py` |

## 11. ESTRATEGIA DE TEST

- **Unit:** cálculo de hash, manifiesto, ordenación y dedupe de timeline.
- **Integración:** caso, evidencia, verificación, export, legal hold.
- **Seguridad:** acceso, integridad, límites, aislamiento.
- **E2E:** `/forensics` con badges de hold y manifiesto.

## 12. EVIDENCIA REQUERIDA

1. `pytest -q tests/integration/test_forensic_export.py tests/integration/test_legal_hold.py tests/security/test_evidence_integrity.py`.
2. Manifiesto JSON con hashes y verificación posterior.
3. Entrada de custodia de descarga con actor/IP/`request_id`.
4. Test de manipulación detectada.
5. ZIP exportado con estructura documentada.
