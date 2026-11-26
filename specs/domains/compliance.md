# DOMINIO: CUMPLIMIENTO NORMATIVO

- **Código:** `CMP`
- **Ruta de implementación:** `backend/app/models/compliance.py`, `backend/app/compliance/frameworks/`, `backend/app/services/{compliance,assessments,nis2,gdpr}.py`, `backend/app/api/v1/{compliance,reports}.py`
- **Estado:** `SPECIFIED`
- **ACs globales:** `AC-88..AC-93`

---

## 1. OBJETIVO

Traducir obligaciones regulatorias en controles verificables, evidencias con vigencia y evaluaciones con gaps accionables, para que el organismo pueda demostrar —no solo afirmar— su postura ante una autoridad, un auditor o un cliente.

## 2. CONTEXTO

NIS2 exige gestión de riesgos, notificación de incidentes en 24 h/72 h/1 mes y responsabilidad de la dirección. El CRA introduce requisitos de seguridad del producto y soporte de actualizaciones. GDPR exige base legal, minimización, registro de tratamientos y evaluación de impacto. ENS (RD 311/2022) establece categorías y medidas. ISO 27001/27002 aportan el sistema de gestión y los controles. IEC 62443 cubre entornos industriales y ETSI EN 303 645 los dispositivos IoT de consumo.

Un control "compliant" sin evidencia es una afirmación sin prueba. Este dominio impide ese estado: el cumplimiento se **deriva** de evidencias aprobadas y vigentes.

## 3. REQUISITOS FUNCIONALES

### 3.1 Catálogo y mapeos

| ID | Requisito | Detalle verificable |
| :--- | :--- | :--- |
| `REQ-CMP-001` | Frameworks | Seed obligatorio: `NIS2` (UE 2022/2555), `CRA` (UE 2024/2847), `GDPR` (UE 2016/679), `ENS` (RD 311/2022), `ISO27001:2022`, `ISO27002:2022`, `IEC62443-3-3`, `ETSI EN 303 645`. Cada uno con `version`, `source_reference`, `controls[]`. |
| `REQ-CMP-002` | Inmutabilidad | Las versiones de framework y de control son inmutables una vez publicadas; un cambio normativo crea nueva versión y marca la anterior `superseded`. |
| `REQ-CMP-003` | Mapeos | `control_mapping` many-to-many entre controles de frameworks distintos con `relationship (equivalent|partial|subset|superset)` y justificación. |
| `REQ-CMP-004` | Aplicabilidad | Un control puede ser `applicable`, `not_applicable` (con justificación) o `inherited` (de otra entidad); solo los aplicables puntúan. |

### 3.2 Evidencias y estado

| ID | Requisito | Detalle verificable |
| :--- | :--- | :--- |
| `REQ-CMP-005` | Evidencia | `evidence_item{control_id, type(document|screenshot|config|report|attestation), file_ref, sha256, valid_from, valid_until, submitted_by, reviewed_by, status(pending|approved|rejected|expired)}`. |
| `REQ-CMP-006` | Aprobación | `auditor` o `owner` aprueba; el solicitante no puede aprobar la suya (`separation_of_duties`). |
| `REQ-CMP-007` | Estado derivado | `compliant` solo si existe evidencia `approved` y vigente; `evidence_expired` si caducó; `partial` si hay evidencia parcial; `non_compliant` si no hay o fue rechazada. No editable manualmente. |
| `REQ-CMP-008` | Caducidad | Job diario recalcula y notifica 30/7/1 días antes de caducar. |
| `REQ-CMP-009` | Gaps | Cada control no conforme genera `gap{severity, remediation, owner, due_at}` y opcionalmente tarea de remediación. |

### 3.3 Evaluaciones e informes

| ID | Requisito | Detalle verificable |
| :--- | :--- | :--- |
| `REQ-CMP-010` | Evaluación | `assessment{framework_version, scope(org|zone|system), state(draft|running|completed|locked), score, methodology_version}`. Score = `100 * (pass + 0.5*partial) / applicable`. |
| `REQ-CMP-011` | Bloqueo | Al completar, la evaluación se bloquea (`locked_at`) y su resultado es inmutable; cambios requieren nueva evaluación. |
| `REQ-CMP-012` | Informe | PDF/JSON con `generated_at`, `framework_versions[]`, `scope`, `score`, `gaps[]`, `evidence_manifest[]` y `content_hash`; descarga auditada. |
| `REQ-CMP-013` | NIS2 tracker | Incidente marcado `nis2_notifiable` → hitos `early_warning` (+24 h), `notification` (+72 h), `final_report` (+1 mes) con estado, responsable y alertas. |
| `REQ-CMP-014` | GDPR | `ropa_entry` (actividad, finalidad, base legal, categorías, destinatarios, retención, transferencias) y `dpia` (necesidad, riesgos, medidas, estado). |
| `REQ-CMP-015` | IEC 62443 / ETSI | Vistas específicas que consumen zonas/conductos y checklist IoT; sin duplicar datos. |

## 4. REQUISITOS NO FUNCIONALES

| ID | Requisito |
| :--- | :--- |
| `NFR-CMP-01` | Seed de 8 frameworks ≤60 s en migración/arranque, idempotente. |
| `NFR-CMP-02` | Evaluación de 500 controles ≤30 s. |
| `NFR-CMP-03` | Informe de 200 páginas ≤60 s con streaming a disco. |
| `NFR-CMP-04` | Recálculo diario de estados de 5.000 controles ≤2 min. |

## 5. DEPENDENCIAS

| Dependencia | Tipo | Nota |
| :--- | :--- | :--- |
| `assets`/`iot`/`ot`/`cloud` | Dominio | Evidencia técnica y alcance |
| `incidents` | Dominio | NIS2 y post-incidente |
| `vulnerabilities` | Dominio | Remediación como evidencia |
| `evidence` storage | Plataforma | Ficheros con hash |
| `reports` | Plataforma | Generación PDF |

## 6. CONTRATOS

| Método | Endpoint | Rol | Entrada | Salida |
| :--- | :--- | :--- | :--- | :--- |
| GET | `/api/v1/compliance/frameworks` | `viewer`+ | — | `200 [{key, version, controls_count, source_reference}]` |
| GET | `/api/v1/compliance/controls` | `viewer`+ | `?framework&status&applicable` | `200` |
| PATCH | `/api/v1/compliance/controls/{id}` | `admin`+ | `{applicability, justification}` | `200` |
| GET/POST | `/api/v1/compliance/mappings` | `auditor`+ | `{from,to,relationship,justification}` | `200/201` |
| POST | `/api/v1/compliance/evidence` | `responder`+ | multipart + metadatos | `201 {evidence_item}` |
| POST | `/api/v1/compliance/evidence/{id}/review` | `auditor`+ | `{decision, comment}` | `200` |
| GET | `/api/v1/compliance/evidence?expiring_in_days=30` | `viewer`+ | — | `200` |
| GET/POST | `/api/v1/compliance/assessments` | `auditor`+ | `{framework_version, scope}` | `200/201` |
| POST | `/api/v1/compliance/assessments/{id}/run` | `auditor`+ | — | `202` |
| GET | `/api/v1/compliance/assessments/{id}` | `viewer`+ | — | `200 {score, results[], gaps[]}` |
| POST | `/api/v1/reports` | `auditor`+ | `{type, framework, scope, format}` | `202 {report_id}` |
| GET | `/api/v1/reports/{id}` | `viewer`+ | — | `200 {meta, content_hash}` |
| GET | `/api/v1/reports/{id}/download` | `viewer`+ | — | `200` binario |
| GET/POST | `/api/v1/compliance/nis2/incidents` | `responder`+ | `{incident_id}` | `200/201` |
| POST | `/api/v1/compliance/nis2/incidents/{id}/milestones/{m}/complete` | `responder`+ | `{evidence_id}` | `200` |
| GET/POST | `/api/v1/compliance/gdpr/ropa` · `/dpia` | `auditor`+ | `RopaEntry` | `200/201` |

## 7. CASOS DE USO

1. **Primera evaluación NIS2:** el `auditor` crea evaluación del framework, el sistema calcula score desde evidencias existentes, produce 18 gaps con severidad y due dates.
2. **Evidencia técnica:** el `responder` sube la política de parcheo aprobada; el `auditor` la revisa y aprueba; el control pasa a `compliant` automáticamente.
3. **Caducidad:** una evidencia de formación caduca; el control vuelve a `evidence_expired` y aparece en el informe de gaps.
4. **Incidente notificable:** incidente P1 con impacto en servicio esencial → se marca `nis2_notifiable` → hitos 24 h/72 h/1 mes con recordatorios.
5. **Inspección:** se genera informe con hash; el inspector verifica el hash del PDF descargado.
6. **IEC 62443:** la vista de cumplimiento OT consume zonas/conductos y muestra gaps por `sl_target`.

## 8. CASOS BORDE

| Escenario | Comportamiento |
| :--- | :--- |
| Marcar `compliant` sin evidencia | `422 evidence_required` |
| Aprobar evidencia propia | `403 separation_of_duties` |
| Evidencia caducada | Estado `evidence_expired`; no puntúa |
| Control `not_applicable` sin justificación | `422 justification_required` |
| Evaluación sobre framework `superseded` | `409 framework_superseded` |
| Modificar evaluación bloqueada | `409 assessment_locked` |
| Informe de evaluación `draft` | `409 assessment_not_completed` |
| Hito NIS2 completado sin evidencia | `422 evidence_required` |
| Hito fuera de plazo | `overdue=true` y alerta a `owner` |
| Mapeo duplicado | `409 mapping_exists` |
| Seed ya ejecutado | Idempotente, sin duplicar controles |
| Framework sin controles (seed corrupto) | Arranque falla la verificación de integridad del catálogo |

## 9. AMENAZAS ESPECÍFICAS

| Amenaza | Vector | Control |
| :--- | :--- | :--- |
| Cumplimiento cosmético | Marcar controles sin prueba | Estado derivado, evidencia obligatoria, revisión separada |
| Evidencia falsificada | Documento inventado | Hash, revisor, muestreo, auditoría |
| Manipulación de fechas | Evidencia retroactiva | `submitted_at` server-side, `valid_from` no anterior a la subida sin justificación |
| Ocultación de gaps | `not_applicable` masivo | Justificación obligatoria, revisión por auditor, alerta si >20% NA |
| Informe alterado | PDF modificado | `content_hash` verificable |

## 10. CRITERIOS DE ACEPTACIÓN

| AC | Criterio | Test |
| :--- | :--- | :--- |
| `AC-88` | 8 frameworks con controles | `backend/tests/integration/test_framework_seed.py` |
| `AC-89` | Estado derivado, no manual | `backend/tests/integration/test_control_status_derivation.py` |
| `AC-90` | Score 40 con 2 pass/1 partial/2 fail | `backend/tests/unit/test_assessment_scoring.py` |
| `AC-91` | Evidencia caducada → gap | `backend/tests/integration/test_evidence_expiry.py` |
| `AC-92` | Tracker NIS2 24/72/1m | `backend/tests/integration/test_nis2_timeline.py` |
| `AC-93` | Informe con hash verificable | `backend/tests/integration/test_report_integrity.py` |
| `AC-CMP-06` | RoPA/DPIA con base legal | `backend/tests/integration/test_gdpr_registry.py` |

## 11. ESTRATEGIA DE TEST

- **Unit:** fórmula de score, derivación de estado, cálculo de hitos NIS2.
- **Integración:** seed, evidencias, revisión, evaluación, informe, GDPR, caducidad.
- **Seguridad:** separación de funciones, manipulación de fechas, aislamiento, integridad de informe.
- **E2E:** `/compliance` con matriz, gaps y evidencia caducada.

## 12. EVIDENCIA REQUERIDA

1. `pytest -q tests/integration/test_framework_seed.py tests/integration/test_assessment_scoring.py tests/integration/test_report_integrity.py`.
2. Conteo de controles por framework y referencia normativa.
3. Evaluación con score calculado y desglose.
4. Informe PDF + hash y verificación de coincidencia.
5. Tracker NIS2 con tres hitos y estados.
